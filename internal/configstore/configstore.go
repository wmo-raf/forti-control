// Package configstore owns the files on the shared volume: the live
// configuration each service reads, and the snapshot of every version the
// controller has ever written.
//
// Writes go through a temporary file and rename(2), so a service watching the
// file sees either the whole old version or the whole new one. Snapshots are
// addressed by the sha256 of their contents, which is the same digest the
// service reports in its status file — that shared digest is what lets the UI
// say whether what is on disk is what is actually being served, and what links
// an audit entry to the bytes it wrote.
package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/metno/forti-control/internal/module"
)

// A Store reads and writes one config directory and one snapshot directory.
type Store struct {
	// ConfigDir holds the live files, one per module, named by Module.File.
	// This is the directory the services read.
	ConfigDir string

	// SnapshotDir holds one subdirectory per module of past versions.
	// Nothing but the controller ever looks at it.
	SnapshotDir string
}

// Content is one module's live configuration file.
type Content struct {
	Data    []byte
	SHA     string
	ModTime time.Time
	Exists  bool
}

// A Snapshot is one stored version of one module's configuration.
type Snapshot struct {
	Module string
	SHA    string
	Taken  time.Time

	// Name is the snapshot's filename. It encodes Taken and the full SHA, so
	// the directory is readable and self-describing without the controller
	// running and without an index.
	Name string

	// written is the snapshot file's modification time, used only to order
	// versions whose filenames put them in the same second.
	written time.Time
}

// Short is the abbreviated digest shown in the UI and in audit entries.
func (s Snapshot) Short() string { return Short(s.SHA) }

// New opens a store, creating both directories if they are not there.
func New(configDir, snapshotDir string) (*Store, error) {
	for _, dir := range []string{configDir, snapshotDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	return &Store{ConfigDir: configDir, SnapshotDir: snapshotDir}, nil
}

// Read returns a module's live configuration. A module whose file does not
// exist yet is not an error: it is a module nobody has configured, and the
// editor opens empty so that somebody can.
func (s *Store) Read(m module.Module) (Content, error) {
	path := s.configPath(m)

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Content{}, nil
	}
	if err != nil {
		return Content{}, err
	}

	var modTime time.Time
	if info, err := os.Stat(path); err == nil {
		modTime = info.ModTime()
	}

	return Content{Data: data, SHA: digest(data), ModTime: modTime, Exists: true}, nil
}

// Save writes data as the module's live configuration and records a snapshot
// of it. The write is atomic; the snapshot is taken after it, so history never
// claims a version that was not written.
//
// Saving bytes that have been saved before returns the existing snapshot
// rather than a second copy of the same content. The audit log, not the
// snapshot directory, is where repeated saves are counted.
func (s *Store) Save(m module.Module, data []byte) (Snapshot, error) {
	if err := writeFileAtomic(s.configPath(m), data); err != nil {
		return Snapshot{}, err
	}
	return s.snapshot(m, data)
}

// Baseline snapshots the current contents of every module that has a file and
// has not been snapshotted before. It runs at startup so that the version
// predating the controller — the one nobody can reconstruct — is in history
// from the first moment, and returns the snapshots it took.
func (s *Store) Baseline(modules []module.Module) ([]Snapshot, error) {
	var taken []Snapshot
	for _, m := range modules {
		content, err := s.Read(m)
		if err != nil {
			return taken, err
		}
		if !content.Exists {
			continue
		}
		if _, err := s.findSnapshot(m, content.SHA); err == nil {
			continue
		}
		snap, err := s.snapshot(m, content.Data)
		if err != nil {
			return taken, err
		}
		taken = append(taken, snap)
	}
	return taken, nil
}

// History lists a module's snapshots, newest first. The time is when the
// controller first saw those bytes, so restoring an old version and saving it
// again does not move it to the top.
func (s *Store) History(m module.Module) ([]Snapshot, error) {
	entries, err := os.ReadDir(s.snapshotDir(m))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var snapshots []Snapshot
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		snap, ok := parseSnapshotName(m.Name, e.Name())
		if !ok {
			continue
		}
		// The filename is the durable record of when a version was first
		// seen: it survives a copy, an rsync or a restore from backup, which
		// a modification time does not. The modification time is kept only to
		// separate versions saved inside the same second, where the filename
		// cannot.
		if info, err := e.Info(); err == nil {
			snap.written = info.ModTime().UTC()
		}
		snapshots = append(snapshots, snap)
	}

	sort.Slice(snapshots, func(i, j int) bool {
		if !snapshots[i].Taken.Equal(snapshots[j].Taken) {
			return snapshots[i].Taken.After(snapshots[j].Taken)
		}
		return snapshots[i].written.After(snapshots[j].written)
	})
	return snapshots, nil
}

// SnapshotData returns the contents of one snapshot, identified by its full
// digest. The digest arrives from a URL, so anything that is not a digest is
// refused before it reaches the filesystem.
func (s *Store) SnapshotData(m module.Module, sha string) ([]byte, error) {
	snap, err := s.findSnapshot(m, sha)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(s.snapshotDir(m), snap.Name))
}

// Snapshot returns the metadata of one stored version.
func (s *Store) Snapshot(m module.Module, sha string) (Snapshot, error) {
	return s.findSnapshot(m, sha)
}

func (s *Store) findSnapshot(m module.Module, sha string) (Snapshot, error) {
	if !isDigest(sha) {
		return Snapshot{}, fmt.Errorf("%q is not a snapshot digest", sha)
	}
	history, err := s.History(m)
	if err != nil {
		return Snapshot{}, err
	}
	for _, snap := range history {
		if snap.SHA == sha {
			return snap, nil
		}
	}
	return Snapshot{}, fmt.Errorf("no snapshot %s of %s", Short(sha), m.Name)
}

// snapshot stores data under a content-addressed name, or returns the
// snapshot already holding those bytes.
func (s *Store) snapshot(m module.Module, data []byte) (Snapshot, error) {
	sha := digest(data)
	if existing, err := s.findSnapshot(m, sha); err == nil {
		return existing, nil
	}

	dir := s.snapshotDir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Snapshot{}, fmt.Errorf("creating %s: %w", dir, err)
	}

	taken := time.Now().UTC()
	snap := Snapshot{
		Module:  m.Name,
		SHA:     sha,
		Taken:   taken.Truncate(time.Second),
		Name:    snapshotName(taken, sha),
		written: taken,
	}
	if err := writeFileAtomic(filepath.Join(dir, snap.Name), data); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func (s *Store) configPath(m module.Module) string {
	return filepath.Join(s.ConfigDir, m.File)
}

func (s *Store) snapshotDir(m module.Module) string {
	return filepath.Join(s.SnapshotDir, m.Name)
}

// ValidateJSON reports everything wrong with data that would stop the
// controller writing it at all, following the convention forti's own
// validators use: all the problems, not the first one. A syntax error hides
// whatever follows it, so in practice this returns at most one — but the
// signature is the one the callers and the page already handle.
//
// This is deliberately shallow: it checks that the file is a JSON object, and
// nothing about what is in it. Whether the contents make sense is the
// service's judgement, made against its own version of the schema — the
// controller has no Go dependency on forti and would only be guessing. What it
// can do is refuse to hand a service a file that is not JSON, since that is a
// mistake with no possible upside.
func ValidateJSON(data []byte) []error {
	if len(strings.TrimSpace(string(data))) == 0 {
		return []error{errors.New("the configuration is empty")}
	}

	var top json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return []error{describeJSONError(data, err)}
	}
	if trimmed := strings.TrimSpace(string(top)); !strings.HasPrefix(trimmed, "{") {
		return []error{errors.New("the configuration must be a JSON object")}
	}
	return nil
}

// describeJSONError turns a byte offset into a line and column, because an
// offset is no help to somebody looking at a textarea.
func describeJSONError(data []byte, err error) error {
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		return err
	}
	line, col := position(data, syntax.Offset)
	return fmt.Errorf("line %d, column %d: %s", line, col, syntax)
}

func position(data []byte, offset int64) (line, col int) {
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	line, col = 1, 1
	for _, b := range data[:offset] {
		if b == '\n' {
			line++
			col = 1
			continue
		}
		col++
	}
	return line, col
}

// writeFileAtomic writes to a temporary file in the destination directory and
// renames it into place. The rename is what makes a watching service safe: it
// replaces the file in one step, so a reader never sees half a config.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// Without this the new contents can outlive the rename only in the page
	// cache, and a machine that loses power comes back to an empty file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// CreateTemp makes the file 0600. Services run as a different user and
	// have to be able to read what the controller writes.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

const snapshotTimeLayout = "20060102T150405Z"

var snapshotNamePattern = regexp.MustCompile(`^(\d{8}T\d{6}Z)-([0-9a-f]{64})\.json$`)

// snapshotName is the timestamp for a human reading the directory, and the
// full digest so that the file is self-describing without an index.
func snapshotName(taken time.Time, sha string) string {
	return fmt.Sprintf("%s-%s.json", taken.Format(snapshotTimeLayout), sha)
}

// parseSnapshotName recovers a snapshot's metadata from its filename and the
// digest file beside it. Names that do not match are ignored rather than
// treated as an error, so an operator's stray copy in the directory does not
// break history.
func parseSnapshotName(moduleName, filename string) (Snapshot, bool) {
	match := snapshotNamePattern.FindStringSubmatch(filename)
	if match == nil {
		return Snapshot{}, false
	}
	taken, err := time.ParseInLocation(snapshotTimeLayout, match[1], time.UTC)
	if err != nil {
		return Snapshot{}, false
	}
	return Snapshot{Module: moduleName, SHA: match[2], Taken: taken, Name: filename}, true
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Short abbreviates a digest to what a person can read and still compare.
func Short(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isDigest(s string) bool { return digestPattern.MatchString(s) }
