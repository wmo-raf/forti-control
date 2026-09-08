// Package status reads what the forti services report about the configuration
// they loaded, and works out what it means for the file the controller wrote.
//
// The status directory is the only channel back from a service. Nothing here
// connects to anything: a service that is not running simply leaves an old
// file, or none, and that absence is itself the answer.
package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/metno/forti-control/internal/module"
)

// ResponseGrace is how long a service is given to notice a new file before
// the UI stops saying "waiting" and starts saying "no response".
//
// Services stat their file once a second, so this is ten chances. Anything
// slower than this is not a slow poll, it is a service that is not running.
const ResponseGrace = 10 * time.Second

// A Status is what a service writes after every attempt to load its
// configuration, successful or not.
//
// This mirrors forti's configwatch.Status. It is declared again here rather
// than imported because the controller has no Go dependency on forti: the
// contract between them is this JSON document, and writing it out twice is
// what keeps it a contract instead of a shared struct.
type Status struct {
	Module         string    `json:"module"`
	LoadedSHA      string    `json:"loaded_sha"`
	LoadedAt       time.Time `json:"loaded_at"`
	OK             bool      `json:"ok"`
	Errors         []string  `json:"errors,omitempty"`
	Applied        []string  `json:"applied,omitempty"`
	PendingRestart []string  `json:"pending_restart,omitempty"`
}

// A Reader reads status files out of the status directory.
//
// The directory is separate from the config directory so that services can be
// given write access to one and read-only access to the other.
type Reader struct {
	Dir string
}

// Read returns what a module last reported, or nil if it has reported
// nothing. A missing file is not an error: it is the normal state of a
// service that has not started yet.
func (r *Reader) Read(m module.Module) (*Status, error) {
	if r.Dir == "" {
		return nil, nil
	}

	data, err := os.ReadFile(filepath.Join(r.Dir, m.StatusFile()))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s is not a status file: %w", m.StatusFile(), err)
	}
	return &s, nil
}

// File is what the controller knows about the configuration file it wrote:
// enough to compare with what the service says it loaded.
type File struct {
	SHA     string
	ModTime time.Time
	Exists  bool
}

// A State is the answer to "is what I saved what is being served?".
type State string

const (
	// StateNoConfig means the module has no configuration file at all.
	StateNoConfig State = "no-config"

	// StateNotWatched means the module does not reload, so a saved file
	// takes effect at the next deploy and no acknowledgement is coming.
	StateNotWatched State = "not-watched"

	// StateLive means the service loaded exactly what is on disk.
	StateLive State = "live"

	// StateRejected means the service read what is on disk and refused it.
	// The previous configuration is still being served.
	StateRejected State = "rejected"

	// StatePending means the service has not reported on the current file
	// yet. It polls once a second, so this is normally over quickly.
	StatePending State = "pending"

	// StateNoResponse means the service should have reported by now and has
	// not. Usually it is not running.
	StateNoResponse State = "no-response"
)

// Headline is the one-line summary the UI shows for a state.
func (s State) Headline() string {
	switch s {
	case StateNoConfig:
		return "No configuration file"
	case StateNotWatched:
		return "Saved — applies on next deploy"
	case StateLive:
		return "Live"
	case StateRejected:
		return "Rejected — still serving the previous configuration"
	case StatePending:
		return "Waiting for the service to pick it up"
	case StateNoResponse:
		return "No response from the service"
	default:
		return "Unknown"
	}
}

// A Verdict is a module's state plus whatever the service said about it.
type Verdict struct {
	Module string
	State  State

	// ServingOlder is true when the running service is using something other
	// than the file on disk. It is the difference between "your change is not
	// live yet" and "your change is live".
	ServingOlder bool

	Errors         []string
	Applied        []string
	PendingRestart []string

	LoadedSHA string
	LoadedAt  time.Time
}

// Headline is the one-line summary the UI shows.
func (v Verdict) Headline() string { return v.State.Headline() }

// IsLive reports whether the service is running the file that is on disk.
//
// It exists so that a page never describes LoadedSHA as the configuration in
// use: that digest is what the service last *read*, which for a rejected
// configuration is precisely the version it is not serving.
func (v Verdict) IsLive() bool { return v.State == StateLive }

// Evaluate compares the file the controller wrote against what the service
// says it loaded.
//
// The comparison is the whole point: a service that reports OK is not
// necessarily serving what was just saved, it may be reporting happily about
// the version before. Only a matching digest means a save went live.
func Evaluate(m module.Module, f File, s *Status, now time.Time) Verdict {
	v := Verdict{Module: m.Name}

	if !f.Exists {
		v.State = StateNoConfig
		return v
	}

	if s == nil {
		// The registry says whether a module is expected to watch its file,
		// but a module that has reported is watching whatever the registry
		// says — so silence is only read as "not watched" when there is no
		// evidence to the contrary.
		if !m.Reloads {
			v.State = StateNotWatched
			return v
		}
		v.State = StateNoResponse
		v.ServingOlder = true
		return v
	}

	v.LoadedSHA = s.LoadedSHA
	v.LoadedAt = s.LoadedAt

	if s.LoadedSHA == f.SHA {
		// The report is about the file on disk, so what it says applies to
		// what was just saved.
		v.Errors = s.Errors
		v.Applied = s.Applied
		v.PendingRestart = s.PendingRestart

		if s.OK {
			v.State = StateLive
			return v
		}
		// The service read this exact file and would not have it. Whatever it
		// is serving, it is not this.
		v.State = StateRejected
		v.ServingOlder = true
		return v
	}

	// The report is about some earlier version. Its errors belong to that
	// version, and showing them here would blame the save just made for
	// something the one before it did — the mistake this whole design exists
	// to stop the operator making.
	v.ServingOlder = true
	if now.Sub(f.ModTime) <= ResponseGrace {
		v.State = StatePending
		return v
	}
	v.State = StateNoResponse
	return v
}
