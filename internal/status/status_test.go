package status

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metno/forti-control/internal/module"
)

var (
	watched   = module.Module{Name: "jsonfrontend", File: "jsonformat.json", Reloads: true}
	unwatched = module.Module{Name: "healthz", File: "probes.json", Reloads: false}
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var now = time.Date(2026, 9, 8, 15, 0, 0, 0, time.UTC)

func fresh(sha string) File {
	return File{SHA: sha, ModTime: now.Add(-time.Second), Exists: true}
}

func TestReadReturnsNothingWhenNoServiceHasReported(t *testing.T) {
	r := &Reader{Dir: t.TempDir()}

	got, err := r.Read(watched)
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	if got != nil {
		t.Errorf("Read = %+v, want nil", got)
	}
}

func TestReadParsesTheStatusFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jsonfrontend.json", `{
	  "module": "jsonfrontend",
	  "loaded_sha": "`+shaA+`",
	  "loaded_at": "2026-09-08T14:02:11Z",
	  "ok": false,
	  "errors": ["two time periods share offset 0"],
	  "applied": ["areas"],
	  "pending_restart": ["source.bucket"]
	}`)
	r := &Reader{Dir: dir}

	got, err := r.Read(watched)
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	if got == nil {
		t.Fatal("Read = nil, want a status")
	}
	if got.LoadedSHA != shaA {
		t.Errorf("LoadedSHA = %q, want %q", got.LoadedSHA, shaA)
	}
	if got.OK {
		t.Error("OK = true, want false")
	}
	if len(got.Errors) != 1 || got.Errors[0] != "two time periods share offset 0" {
		t.Errorf("Errors = %q", got.Errors)
	}
	if len(got.Applied) != 1 || got.Applied[0] != "areas" {
		t.Errorf("Applied = %q", got.Applied)
	}
	if len(got.PendingRestart) != 1 || got.PendingRestart[0] != "source.bucket" {
		t.Errorf("PendingRestart = %q", got.PendingRestart)
	}
	if want := time.Date(2026, 9, 8, 14, 2, 11, 0, time.UTC); !got.LoadedAt.Equal(want) {
		t.Errorf("LoadedAt = %s, want %s", got.LoadedAt, want)
	}
}

// A service writes its status with a temporary file and a rename, but a
// truncated or hand-mangled file must not take the page down.
func TestReadReportsAnUnreadableStatusFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jsonfrontend.json", `{"module": `)
	r := &Reader{Dir: dir}

	if _, err := r.Read(watched); err == nil {
		t.Error("Read of a truncated status file succeeded, want an error")
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name   string
		module module.Module
		file   File
		status *Status
		want   State
	}{
		{
			name:   "no config file yet",
			module: watched,
			file:   File{},
			want:   StateNoConfig,
		},
		{
			name:   "a module that does not watch its file",
			module: unwatched,
			file:   fresh(shaA),
			want:   StateNotWatched,
		},
		{
			name:   "the service loaded what is on disk",
			module: watched,
			file:   fresh(shaA),
			status: &Status{LoadedSHA: shaA, OK: true},
			want:   StateLive,
		},
		{
			name:   "the service refused what is on disk",
			module: watched,
			file:   fresh(shaA),
			status: &Status{LoadedSHA: shaA, OK: false, Errors: []string{"nope"}},
			want:   StateRejected,
		},
		{
			name:   "the service has not caught up yet",
			module: watched,
			file:   fresh(shaB),
			status: &Status{LoadedSHA: shaA, OK: true},
			want:   StatePending,
		},
		{
			name:   "the service never caught up",
			module: watched,
			file:   File{SHA: shaB, ModTime: now.Add(-time.Hour), Exists: true},
			status: &Status{LoadedSHA: shaA, OK: true},
			want:   StateNoResponse,
		},
		{
			name:   "a watching module that has reported nothing",
			module: watched,
			file:   fresh(shaA),
			want:   StateNoResponse,
		},
		{
			// The table in the module registry is a default, not evidence.
			// A status file means the service is watching, whatever the
			// controller was compiled believing.
			name:   "a module reported as not watching, that reported anyway",
			module: unwatched,
			file:   fresh(shaA),
			status: &Status{LoadedSHA: shaA, OK: true},
			want:   StateLive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.module, tt.file, tt.status, now)
			if got.State != tt.want {
				t.Errorf("State = %q, want %q", got.State, tt.want)
			}
		})
	}
}

// This is the case the whole design exists to make visible: the file on disk
// is bad, and the service is still serving the version before it.
func TestARejectedVerdictCarriesTheReasons(t *testing.T) {
	got := Evaluate(watched, fresh(shaA), &Status{
		LoadedSHA: shaA,
		OK:        false,
		Errors:    []string{"two time periods share offset 0", "empty external name"},
	}, now)

	if got.State != StateRejected {
		t.Fatalf("State = %q, want %q", got.State, StateRejected)
	}
	if len(got.Errors) != 2 {
		t.Errorf("Errors = %q, want both", got.Errors)
	}
	if !got.ServingOlder {
		t.Error("ServingOlder = false; a rejected config means the previous one is still in use")
	}
}

func TestALiveVerdictIsNotServingSomethingOlder(t *testing.T) {
	got := Evaluate(watched, fresh(shaA), &Status{LoadedSHA: shaA, OK: true}, now)

	if got.ServingOlder {
		t.Error("ServingOlder = true for a config that was applied")
	}
}

func TestEveryStateHasAHeadline(t *testing.T) {
	states := []State{StateNoConfig, StateNotWatched, StateLive, StateRejected, StatePending, StateNoResponse}
	for _, s := range states {
		t.Run(string(s), func(t *testing.T) {
			if s.Headline() == "" {
				t.Errorf("state %q has no headline", s)
			}
		})
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %s", name, err)
	}
}

// loaded_sha is what the service last read. Calling it the configuration in
// use would contradict the verdict directly above it on a rejected save.
func TestOnlyALiveVerdictIsLive(t *testing.T) {
	tests := []struct {
		name   string
		file   File
		status *Status
		want   bool
	}{
		{"applied", fresh(shaA), &Status{LoadedSHA: shaA, OK: true}, true},
		{"refused", fresh(shaA), &Status{LoadedSHA: shaA, OK: false, Errors: []string{"nope"}}, false},
		{"not caught up", fresh(shaB), &Status{LoadedSHA: shaA, OK: true}, false},
		{"nothing reported", fresh(shaA), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(watched, tt.file, tt.status, now).IsLive(); got != tt.want {
				t.Errorf("IsLive = %t, want %t", got, tt.want)
			}
		})
	}
}

// A report about an earlier version says nothing about the one just saved.
// Showing its errors would blame the new save for the old one's problems.
func TestErrorsFromAnEarlierVersionAreNotShownAgainstTheNewOne(t *testing.T) {
	got := Evaluate(watched, fresh(shaB), &Status{
		LoadedSHA:      shaA,
		OK:             false,
		Errors:         []string{"a problem with the version before this one"},
		Applied:        []string{"parameters"},
		PendingRestart: []string{"source.bucket"},
	}, now)

	if got.State != StatePending {
		t.Fatalf("State = %q, want %q", got.State, StatePending)
	}
	if len(got.Errors) != 0 {
		t.Errorf("Errors = %q; they belong to a version that is no longer on disk", got.Errors)
	}
	if len(got.Applied) != 0 {
		t.Errorf("Applied = %q; it describes an earlier version", got.Applied)
	}
	if len(got.PendingRestart) != 0 {
		t.Errorf("PendingRestart = %q; it describes an earlier version", got.PendingRestart)
	}
	// The digest is still worth showing: it says which version the service is
	// actually on, which is the useful part of a stale report.
	if got.LoadedSHA != shaA {
		t.Errorf("LoadedSHA = %q, want the version the service last read", got.LoadedSHA)
	}
}
