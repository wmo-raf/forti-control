package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("Open: %s", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %s", err)
	}
	if _, err := first.CreateUser("admin", "hunter2hunter2"); err != nil {
		t.Fatalf("CreateUser: %s", err)
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %s", err)
	}
	defer second.Close()

	if _, err := second.Authenticate("admin", "hunter2hunter2"); err != nil {
		t.Errorf("the user did not survive reopening: %s", err)
	}
}

func TestAuthenticateAcceptsTheRightPassword(t *testing.T) {
	db := open(t)
	created, err := db.CreateUser("admin", "correct horse battery")
	if err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	got, err := db.Authenticate("admin", "correct horse battery")
	if err != nil {
		t.Fatalf("Authenticate: %s", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %d, want %d", got.ID, created.ID)
	}
	if got.Name != "admin" {
		t.Errorf("Name = %q, want admin", got.Name)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	db := open(t)
	if _, err := db.CreateUser("admin", "correct horse battery"); err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	tests := []struct {
		name, user, password string
	}{
		{"the wrong password", "admin", "incorrect horse battery"},
		{"an unknown user", "nobody", "correct horse battery"},
		{"an empty password", "admin", ""},
		{"a password that is a prefix of the right one", "admin", "correct"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := db.Authenticate(tt.user, tt.password); !errors.Is(err, ErrNoSuchUser) {
				t.Errorf("Authenticate = %v, want ErrNoSuchUser", err)
			}
		})
	}
}

func TestPasswordsAreNotStoredInTheClear(t *testing.T) {
	db := open(t)
	const password = "a memorable passphrase"
	if _, err := db.CreateUser("admin", password); err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	var hash string
	if err := db.sql.QueryRow(`SELECT password_hash FROM users WHERE name = 'admin'`).Scan(&hash); err != nil {
		t.Fatalf("reading the stored hash: %s", err)
	}
	if strings.Contains(hash, password) {
		t.Error("the stored hash contains the password")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash = %q, want a bcrypt hash", hash)
	}
}

func TestCreateUserRejectsADuplicateName(t *testing.T) {
	db := open(t)
	if _, err := db.CreateUser("admin", "hunter2hunter2"); err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	if _, err := db.CreateUser("admin", "something else"); err == nil {
		t.Error("creating a second user with the same name succeeded")
	}
}

func TestCreateUserRejectsAShortPassword(t *testing.T) {
	db := open(t)

	if _, err := db.CreateUser("admin", "short"); err == nil {
		t.Error("CreateUser accepted a five-character password")
	}
}

func TestSeedAdminCreatesTheFirstUser(t *testing.T) {
	db := open(t)

	created, err := db.SeedAdmin("admin", "a good long password")
	if err != nil {
		t.Fatalf("SeedAdmin: %s", err)
	}
	if !created {
		t.Fatal("SeedAdmin reported no user created on an empty database")
	}
	if _, err := db.Authenticate("admin", "a good long password"); err != nil {
		t.Errorf("Authenticate: %s", err)
	}
}

// Restarting the controller must not reset the administrator's password back
// to whatever is in the environment.
func TestSeedAdminLeavesAnExistingUserAlone(t *testing.T) {
	db := open(t)
	if _, err := db.CreateUser("admin", "the password in use"); err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	created, err := db.SeedAdmin("admin", "a different password")
	if err != nil {
		t.Fatalf("SeedAdmin: %s", err)
	}
	if created {
		t.Error("SeedAdmin created a user over an existing one")
	}
	if _, err := db.Authenticate("admin", "the password in use"); err != nil {
		t.Errorf("the existing password stopped working: %s", err)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	db := open(t)
	user, err := db.CreateUser("admin", "a good long password")
	if err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	token, err := db.NewSession(user.ID, time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %s", err)
	}
	if len(token) < 32 {
		t.Errorf("token %q is too short to be unguessable", token)
	}

	got, err := db.SessionUser(token)
	if err != nil {
		t.Fatalf("SessionUser: %s", err)
	}
	if got.Name != "admin" {
		t.Errorf("Name = %q, want admin", got.Name)
	}
}

func TestSessionsAreUnique(t *testing.T) {
	db := open(t)
	user, err := db.CreateUser("admin", "a good long password")
	if err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	seen := map[string]bool{}
	for range 50 {
		token, err := db.NewSession(user.ID, time.Hour)
		if err != nil {
			t.Fatalf("NewSession: %s", err)
		}
		if seen[token] {
			t.Fatalf("token %q issued twice", token)
		}
		seen[token] = true
	}
}

func TestSessionUserRejects(t *testing.T) {
	db := open(t)
	user, err := db.CreateUser("admin", "a good long password")
	if err != nil {
		t.Fatalf("CreateUser: %s", err)
	}

	expired, err := db.NewSession(user.ID, -time.Minute)
	if err != nil {
		t.Fatalf("NewSession: %s", err)
	}
	logout, err := db.NewSession(user.ID, time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %s", err)
	}
	if err := db.DeleteSession(logout); err != nil {
		t.Fatalf("DeleteSession: %s", err)
	}

	for name, token := range map[string]string{
		"an expired session":   expired,
		"a logged-out session": logout,
		"an invented token":    "0000000000000000000000000000000000000000000",
		"no token":             "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := db.SessionUser(token); !errors.Is(err, ErrNoSession) {
				t.Errorf("SessionUser = %v, want ErrNoSession", err)
			}
		})
	}
}

func TestAuditRecordsAreReturnedNewestFirst(t *testing.T) {
	db := open(t)

	for _, note := range []string{"first", "second", "third"} {
		if err := db.Record(Entry{Module: "jsonfrontend", Action: ActionSave, User: "admin", Note: note}); err != nil {
			t.Fatalf("Record: %s", err)
		}
	}

	entries, err := db.Audit("", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	for i, want := range []string{"third", "second", "first"} {
		if entries[i].Note != want {
			t.Errorf("entries[%d].Note = %q, want %q", i, entries[i].Note, want)
		}
	}
}

// The linkage the design is for: an audit entry names the snapshot holding
// the bytes it wrote, so history can answer "what did it say before?".
func TestAuditEntriesKeepTheSnapshotLinkage(t *testing.T) {
	db := open(t)
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const previous = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	if err := db.Record(Entry{
		Module:       "jsonfrontend",
		Action:       ActionSave,
		User:         "admin",
		SnapshotSHA:  sha,
		SnapshotName: "20260908T150000Z-" + sha + ".json",
		PreviousSHA:  previous,
	}); err != nil {
		t.Fatalf("Record: %s", err)
	}

	entries, err := db.Audit("jsonfrontend", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.SnapshotSHA != sha {
		t.Errorf("SnapshotSHA = %q, want %q", got.SnapshotSHA, sha)
	}
	if got.PreviousSHA != previous {
		t.Errorf("PreviousSHA = %q, want %q", got.PreviousSHA, previous)
	}
	if got.At.IsZero() {
		t.Error("At is zero; an audit entry with no time is not an audit entry")
	}
}

func TestAuditFiltersByModule(t *testing.T) {
	db := open(t)
	for _, m := range []string{"jsonfrontend", "healthz", "jsonfrontend"} {
		if err := db.Record(Entry{Module: m, Action: ActionSave, User: "admin"}); err != nil {
			t.Fatalf("Record: %s", err)
		}
	}

	entries, err := db.Audit("healthz", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Module != "healthz" {
		t.Errorf("Module = %q, want healthz", entries[0].Module)
	}
}

func TestAuditHonoursTheLimit(t *testing.T) {
	db := open(t)
	for range 10 {
		if err := db.Record(Entry{Module: "jsonfrontend", Action: ActionSave, User: "admin"}); err != nil {
			t.Fatalf("Record: %s", err)
		}
	}

	entries, err := db.Audit("", 4)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 4 {
		t.Errorf("got %d entries, want 4", len(entries))
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	db := open(t)

	if got, err := db.setting("absent"); err != nil || got != "" {
		t.Errorf("Setting(absent) = %q, %v; want \"\", nil", got, err)
	}
	if err := db.setSetting("greeting", "hello"); err != nil {
		t.Fatalf("SetSetting: %s", err)
	}
	if got, _ := db.setting("greeting"); got != "hello" {
		t.Errorf("Setting = %q, want hello", got)
	}
	if err := db.setSetting("greeting", "goodbye"); err != nil {
		t.Fatalf("SetSetting over an existing key: %s", err)
	}
	if got, _ := db.setting("greeting"); got != "goodbye" {
		t.Errorf("Setting = %q, want goodbye", got)
	}
}

// CSRF tokens are derived from this key, so a restart that changed it would
// reject the first save from every open tab.
func TestSecretKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %s", err)
	}
	key, err := first.SecretKey("csrf")
	if err != nil {
		t.Fatalf("SecretKey: %s", err)
	}
	if len(key) != 32 {
		t.Errorf("key is %d bytes, want 32", len(key))
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %s", err)
	}
	defer second.Close()

	again, err := second.SecretKey("csrf")
	if err != nil {
		t.Fatalf("SecretKey after reopening: %s", err)
	}
	if string(again) != string(key) {
		t.Error("the secret key changed across a restart")
	}
}
