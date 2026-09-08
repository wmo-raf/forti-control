package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metno/forti-control/internal/module"
)

var testModule = module.Module{Name: "jsonfrontend", File: "jsonformat.json"}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "config"), filepath.Join(dir, "snapshots"))
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	return s
}

func sha(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func TestReadMissingFileIsNotAnError(t *testing.T) {
	s := newStore(t)

	got, err := s.Read(testModule)
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	if got.Exists {
		t.Error("Exists = true for a file that was never written")
	}
	if len(got.Data) != 0 {
		t.Errorf("Data = %q, want empty", got.Data)
	}
}

func TestSaveThenRead(t *testing.T) {
	s := newStore(t)
	const content = `{"areas": ["no"]}`

	if _, err := s.Save(testModule, []byte(content)); err != nil {
		t.Fatalf("Save: %s", err)
	}

	got, err := s.Read(testModule)
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	if !got.Exists {
		t.Error("Exists = false after Save")
	}
	if string(got.Data) != content {
		t.Errorf("Data = %q, want %q", got.Data, content)
	}
	if got.SHA != sha(content) {
		t.Errorf("SHA = %s, want %s", got.SHA, sha(content))
	}
}

// The digest has to be the plain sha256 of the file's bytes, because that is
// what the service reports back in loaded_sha. If the two ever disagree the
// status panel can never say a save went live.
func TestSHAMatchesTheBytesOnDisk(t *testing.T) {
	s := newStore(t)
	const content = `{"a":1}`

	snap, err := s.Save(testModule, []byte(content))
	if err != nil {
		t.Fatalf("Save: %s", err)
	}
	if snap.SHA != sha(content) {
		t.Errorf("snapshot SHA = %s, want %s", snap.SHA, sha(content))
	}

	onDisk, err := os.ReadFile(filepath.Join(s.ConfigDir, testModule.File))
	if err != nil {
		t.Fatalf("reading the config file: %s", err)
	}
	if string(onDisk) != content {
		t.Errorf("file on disk = %q, want %q", onDisk, content)
	}
}

func TestSaveLeavesNoTemporaryFiles(t *testing.T) {
	s := newStore(t)

	if _, err := s.Save(testModule, []byte(`{}`)); err != nil {
		t.Fatalf("Save: %s", err)
	}

	entries, err := os.ReadDir(s.ConfigDir)
	if err != nil {
		t.Fatalf("ReadDir: %s", err)
	}
	for _, e := range entries {
		if e.Name() != testModule.File {
			t.Errorf("stray file %q left in the config directory", e.Name())
		}
	}
}

// Services run as an unprivileged user and only read these files, so the
// file has to stay readable to them after a rename from a fresh temp file.
func TestSavedFileIsWorldReadable(t *testing.T) {
	s := newStore(t)

	if _, err := s.Save(testModule, []byte(`{}`)); err != nil {
		t.Fatalf("Save: %s", err)
	}

	info, err := os.Stat(filepath.Join(s.ConfigDir, testModule.File))
	if err != nil {
		t.Fatalf("Stat: %s", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
}

func TestSaveSnapshotsTheNewContent(t *testing.T) {
	s := newStore(t)
	const content = `{"offer_gzip": true}`

	snap, err := s.Save(testModule, []byte(content))
	if err != nil {
		t.Fatalf("Save: %s", err)
	}

	got, err := s.SnapshotData(testModule, snap.SHA)
	if err != nil {
		t.Fatalf("SnapshotData: %s", err)
	}
	if string(got) != content {
		t.Errorf("snapshot content = %q, want %q", got, content)
	}
}

// Snapshots are addressed by content, so saving the same bytes twice must not
// produce a second copy. The audit log still gets an entry for each save.
func TestSavingIdenticalContentReusesTheSnapshot(t *testing.T) {
	s := newStore(t)

	first, err := s.Save(testModule, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("first Save: %s", err)
	}
	second, err := s.Save(testModule, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("second Save: %s", err)
	}

	if first.Name != second.Name {
		t.Errorf("snapshot names differ: %q then %q", first.Name, second.Name)
	}
	history, err := s.History(testModule)
	if err != nil {
		t.Fatalf("History: %s", err)
	}
	if len(history) != 1 {
		t.Errorf("history has %d entries, want 1", len(history))
	}
}

func TestHistoryIsNewestFirst(t *testing.T) {
	s := newStore(t)

	for _, content := range []string{`{"v":1}`, `{"v":2}`, `{"v":3}`} {
		if _, err := s.Save(testModule, []byte(content)); err != nil {
			t.Fatalf("Save %s: %s", content, err)
		}
	}

	history, err := s.History(testModule)
	if err != nil {
		t.Fatalf("History: %s", err)
	}
	if len(history) != 3 {
		t.Fatalf("history has %d entries, want 3", len(history))
	}
	for i, want := range []string{`{"v":3}`, `{"v":2}`, `{"v":1}`} {
		data, err := s.SnapshotData(testModule, history[i].SHA)
		if err != nil {
			t.Fatalf("SnapshotData: %s", err)
		}
		if string(data) != want {
			t.Errorf("history[%d] = %q, want %q", i, data, want)
		}
	}
}

func TestHistoryOfAnUnknownModuleIsEmpty(t *testing.T) {
	s := newStore(t)

	history, err := s.History(testModule)
	if err != nil {
		t.Fatalf("History: %s", err)
	}
	if len(history) != 0 {
		t.Errorf("history has %d entries, want 0", len(history))
	}
}

// Whatever was on the volume before the controller existed is the version
// people will want to go back to when the first edit goes wrong.
func TestBaselineSnapshotsWhatIsAlreadyThere(t *testing.T) {
	s := newStore(t)
	const existing = `{"pre": "controller"}`
	if err := os.WriteFile(filepath.Join(s.ConfigDir, testModule.File), []byte(existing), 0o644); err != nil {
		t.Fatalf("seeding the config file: %s", err)
	}

	taken, err := s.Baseline([]module.Module{testModule})
	if err != nil {
		t.Fatalf("Baseline: %s", err)
	}
	if len(taken) != 1 {
		t.Fatalf("Baseline took %d snapshots, want 1", len(taken))
	}

	data, err := s.SnapshotData(testModule, taken[0].SHA)
	if err != nil {
		t.Fatalf("SnapshotData: %s", err)
	}
	if string(data) != existing {
		t.Errorf("snapshot = %q, want %q", data, existing)
	}
}

func TestBaselineIsIdempotent(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(filepath.Join(s.ConfigDir, testModule.File), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("seeding the config file: %s", err)
	}

	if _, err := s.Baseline([]module.Module{testModule}); err != nil {
		t.Fatalf("first Baseline: %s", err)
	}
	taken, err := s.Baseline([]module.Module{testModule})
	if err != nil {
		t.Fatalf("second Baseline: %s", err)
	}
	if len(taken) != 0 {
		t.Errorf("second Baseline took %d snapshots, want 0", len(taken))
	}
}

func TestBaselineSkipsModulesWithNoFile(t *testing.T) {
	s := newStore(t)

	taken, err := s.Baseline([]module.Module{testModule})
	if err != nil {
		t.Fatalf("Baseline: %s", err)
	}
	if len(taken) != 0 {
		t.Errorf("Baseline took %d snapshots for a module with no file, want 0", len(taken))
	}
}

func TestSnapshotDataRejectsAnUnknownDigest(t *testing.T) {
	s := newStore(t)

	if _, err := s.SnapshotData(testModule, sha("never saved")); err == nil {
		t.Error("SnapshotData of an unknown digest succeeded, want an error")
	}
}

// A digest arrives from a URL, so it must not be usable to read arbitrary
// files off the volume.
func TestSnapshotDataRejectsAPathTraversal(t *testing.T) {
	s := newStore(t)
	if _, err := s.Save(testModule, []byte(`{}`)); err != nil {
		t.Fatalf("Save: %s", err)
	}

	for _, digest := range []string{"../../etc/passwd", "..", "/etc/passwd", ""} {
		if _, err := s.SnapshotData(testModule, digest); err == nil {
			t.Errorf("SnapshotData(%q) succeeded, want an error", digest)
		}
	}
}

func TestValidateJSONRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"truncated", `{"a": `},
		{"trailing comma", `{"a": 1,}`},
		{"bare text", `not json at all`},
		{"empty", ``},
		{"a list", `[1, 2, 3]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if problems := ValidateJSON([]byte(tt.in)); len(problems) == 0 {
				t.Errorf("ValidateJSON(%q) found nothing wrong", tt.in)
			}
		})
	}
}

func TestValidateJSONAcceptsAnObject(t *testing.T) {
	if problems := ValidateJSON([]byte(`{"a": {"b": [1, 2]}}`)); len(problems) != 0 {
		t.Errorf("ValidateJSON: %v", problems)
	}
}

// The message goes straight into the editor page, so it has to say where the
// problem is.
func TestValidateJSONSaysWhereTheProblemIs(t *testing.T) {
	problems := ValidateJSON([]byte("{\n  \"a\": 1,\n  \"b\": oops\n}"))
	if len(problems) != 1 {
		t.Fatalf("ValidateJSON found %d problems, want 1", len(problems))
	}
	if !strings.Contains(problems[0].Error(), "line 3") {
		t.Errorf("error %q does not mention line 3", problems[0])
	}
}

// The timestamp in the filename is the durable record. A copy, an rsync or a
// restore from backup resets modification times; history must survive that.
func TestHistoryOrdersByTheTimestampInTheName(t *testing.T) {
	s := newStore(t)
	dir := filepath.Join(s.SnapshotDir, testModule.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %s", err)
	}

	// Written oldest-last, as a copy that walked the directory might.
	for _, snap := range []struct{ name, content string }{
		{"20260101T000000Z-" + sha(`{"v":1}`) + ".json", `{"v":1}`},
		{"20260601T000000Z-" + sha(`{"v":2}`) + ".json", `{"v":2}`},
		{"20260901T000000Z-" + sha(`{"v":3}`) + ".json", `{"v":3}`},
	} {
		if err := os.WriteFile(filepath.Join(dir, snap.name), []byte(snap.content), 0o644); err != nil {
			t.Fatalf("writing %s: %s", snap.name, err)
		}
	}

	history, err := s.History(testModule)
	if err != nil {
		t.Fatalf("History: %s", err)
	}
	if len(history) != 3 {
		t.Fatalf("history has %d entries, want 3", len(history))
	}
	for i, want := range []string{`{"v":3}`, `{"v":2}`, `{"v":1}`} {
		data, err := s.SnapshotData(testModule, history[i].SHA)
		if err != nil {
			t.Fatalf("SnapshotData: %s", err)
		}
		if string(data) != want {
			t.Errorf("history[%d] = %q, want %q", i, data, want)
		}
	}
	if want := 2026; history[0].Taken.Year() != want {
		t.Errorf("Taken = %s, want the time from the filename", history[0].Taken)
	}
}
