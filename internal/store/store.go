// Package store keeps the controller's own state: who may log in, who is
// logged in, and what everybody did.
//
// None of this is forti configuration. The configuration lives in files on the
// shared volume and stays authoritative there — see package configstore. What
// is here is the controller's private bookkeeping, which has no reason to be
// on the volume the services read, and which wants real queries.
//
// The audit log references snapshots by digest rather than storing what was
// written. That linkage is the point: the log says who changed what and when,
// and the digest leads to the exact bytes.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // a cgo-free driver, so the controller cross-builds
)

// ErrNoSuchUser is returned for both a wrong password and an unknown name.
// Which of the two it was is not something a login form should reveal.
var ErrNoSuchUser = errors.New("no such user, or wrong password")

// ErrNoSession is returned for a token that is unknown, expired, or logged
// out.
var ErrNoSession = errors.New("not signed in")

// MinPasswordLength is short enough not to annoy and long enough that bcrypt
// is doing real work.
const MinPasswordLength = 12

// A User may sign in and change configuration.
type User struct {
	ID      int64
	Name    string
	Created time.Time
}

// An Action is what an audit entry records.
type Action string

const (
	// ActionSave is a configuration written from the editor.
	ActionSave Action = "save"

	// ActionRestore is an old snapshot written back as the live file. It is
	// an ordinary save of old content, recorded differently so that history
	// reads honestly.
	ActionRestore Action = "restore"

	// ActionBaseline is the controller recording what it found on the volume
	// when it first started, which nobody performed.
	ActionBaseline Action = "baseline"

	// ActionRejected is a save the controller would not write, because what
	// was submitted was not JSON. Nothing reached the volume.
	ActionRejected Action = "rejected"
)

// An Entry is one line of the audit log.
type Entry struct {
	ID     int64
	At     time.Time
	User   string
	Module string
	Action Action

	// SnapshotSHA and SnapshotName point at the bytes this entry wrote.
	// Both are empty for an entry that wrote nothing.
	SnapshotSHA  string
	SnapshotName string

	// PreviousSHA is what the live file held before. It is what makes the log
	// answer "what did it say before?" without reading the entry before it.
	PreviousSHA string

	Note string
}

// A DB is the controller's database. The handle is unexported so that every
// query lives in this package: the rest of the controller asks for users,
// sessions and audit entries, never for rows.
type DB struct {
	sql *sql.DB
}

// Close closes the database.
func (db *DB) Close() error { return db.sql.Close() }

// Open opens the database at path, creating it and its schema if needed.
func Open(path string) (*DB, error) {
	// WAL so that a read never blocks the save that is in flight; a busy
	// timeout so that two browser tabs saving at once wait rather than fail.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db := &DB{sql: sqlDB}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY,
	name          TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token      TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
	id            INTEGER PRIMARY KEY,
	at            TEXT NOT NULL,
	user_name     TEXT NOT NULL,
	module        TEXT NOT NULL,
	action        TEXT NOT NULL,
	snapshot_sha  TEXT NOT NULL DEFAULT '',
	snapshot_name TEXT NOT NULL DEFAULT '',
	previous_sha  TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_module_id ON audit (module, id DESC);

CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`
	_, err := db.sql.Exec(schema)
	return err
}

// CreateUser adds a user with a bcrypt-hashed password.
func (db *DB) CreateUser(name, password string) (User, error) {
	if name == "" {
		return User{}, errors.New("a user needs a name")
	}
	if len(password) < MinPasswordLength {
		return User{}, fmt.Errorf("a password must be at least %d characters", MinPasswordLength)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	created := time.Now().UTC()
	result, err := db.sql.Exec(
		`INSERT INTO users (name, password_hash, created_at) VALUES (?, ?, ?)`,
		name, string(hash), created.Format(time.RFC3339Nano))
	if err != nil {
		return User{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return User{ID: id, Name: name, Created: created}, nil
}

// SeedAdmin creates the named user if the database has no users at all, and
// reports whether it did.
//
// It deliberately does nothing once anybody exists: the seed password comes
// from the environment, and a controller restart must not put it back over a
// password somebody has since changed.
func (db *DB) SeedAdmin(name, password string) (bool, error) {
	var count int
	if err := db.sql.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		return false, err
	}
	if count > 0 {
		return false, nil
	}
	if _, err := db.CreateUser(name, password); err != nil {
		return false, err
	}
	return true, nil
}

// Authenticate returns the user with this name and password.
func (db *DB) Authenticate(name, password string) (User, error) {
	var (
		user    User
		hash    string
		created string
	)
	err := db.sql.QueryRow(
		`SELECT id, name, password_hash, created_at FROM users WHERE name = ?`, name).
		Scan(&user.ID, &user.Name, &hash, &created)

	if errors.Is(err, sql.ErrNoRows) {
		// Hash something anyway, so that an unknown name does not answer
		// faster than a known one.
		bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return User{}, ErrNoSuchUser
	}
	if err != nil {
		return User{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, ErrNoSuchUser
	}
	user.Created, _ = time.Parse(time.RFC3339Nano, created)
	return user, nil
}

// dummyHash is a valid bcrypt hash of a value nobody will guess. It exists
// only to be compared against, so that failing early on an unknown user is not
// measurably faster than failing on a wrong password.
const dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// NewSession issues a session token for a user, valid for ttl.
func (db *DB) NewSession(userID int64, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	now := time.Now().UTC()
	_, err := db.sql.Exec(
		`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	return token, nil
}

// SessionUser returns the signed-in user for a token.
func (db *DB) SessionUser(token string) (User, error) {
	if token == "" {
		return User{}, ErrNoSession
	}

	var (
		user    User
		expires string
	)
	err := db.sql.QueryRow(`
		SELECT users.id, users.name, sessions.expires_at
		FROM sessions JOIN users ON users.id = sessions.user_id
		WHERE sessions.token = ?`, token).
		Scan(&user.ID, &user.Name, &expires)

	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNoSession
	}
	if err != nil {
		return User{}, err
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !time.Now().UTC().Before(expiresAt) {
		return User{}, ErrNoSession
	}
	return user, nil
}

// DeleteSession signs a session out.
func (db *DB) DeleteSession(token string) error {
	_, err := db.sql.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// DeleteExpiredSessions removes sessions nobody can use any more.
func (db *DB) DeleteExpiredSessions() error {
	_, err := db.sql.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// Record appends an audit entry. The time is set here rather than by the
// caller so that the log is in the database's order.
func (db *DB) Record(e Entry) error {
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := db.sql.Exec(`
		INSERT INTO audit (at, user_name, module, action, snapshot_sha, snapshot_name, previous_sha, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		at.Format(time.RFC3339Nano), e.User, e.Module, string(e.Action),
		e.SnapshotSHA, e.SnapshotName, e.PreviousSHA, e.Note)
	return err
}

// Audit returns the newest entries, for one module or for all of them if
// moduleName is empty.
func (db *DB) Audit(moduleName string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, at, user_name, module, action, snapshot_sha, snapshot_name, previous_sha, note
		FROM audit`
	args := []any{}
	if moduleName != "" {
		query += ` WHERE module = ?`
		args = append(args, moduleName)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var (
			e      Entry
			at     string
			action string
		)
		if err := rows.Scan(&e.ID, &at, &e.User, &e.Module, &action,
			&e.SnapshotSHA, &e.SnapshotName, &e.PreviousSHA, &e.Note); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.Action = Action(action)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// setting returns a stored controller setting, or "" if it has never been
// set.
func (db *DB) setting(key string) (string, error) {
	var value string
	err := db.sql.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

// setSetting stores a controller setting.
func (db *DB) setSetting(key, value string) error {
	_, err := db.sql.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// SecretKey returns a random key generated once and kept, so that things
// derived from it — CSRF tokens, for one — survive a restart.
func (db *DB) SecretKey(name string) ([]byte, error) {
	stored, err := db.setting(name)
	if err != nil {
		return nil, err
	}
	if stored != "" {
		return hex.DecodeString(stored)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := db.setSetting(name, hex.EncodeToString(key)); err != nil {
		return nil, err
	}
	return key, nil
}
