package module

import "testing"

func TestParseEmptyIsEverything(t *testing.T) {
	got, err := Parse("")
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	if len(got) != len(All) {
		t.Errorf("got %d modules, want all %d", len(got), len(All))
	}
}

func TestParseSelectsModules(t *testing.T) {
	got, err := Parse("jsonfrontend, healthz")
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d modules, want 2", len(got))
	}
	if got[0].Name != "jsonfrontend" || got[1].Name != "healthz" {
		t.Errorf("got %q and %q", got[0].Name, got[1].Name)
	}
	if got[0].Title == "" {
		t.Error("a selected module lost the title from the registry")
	}
}

// A deployment runs rawdataforecaster once per product, and each instance
// reads a different file.
func TestParseTakesTheFileTheDeploymentUses(t *testing.T) {
	got, err := Parse("rawdataforecaster=oceanforecast.json")
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	if got[0].File != "oceanforecast.json" {
		t.Errorf("File = %q, want oceanforecast.json", got[0].File)
	}
	if got[0].Name != "rawdataforecaster" {
		t.Errorf("Name = %q", got[0].Name)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct{ name, spec string }{
		{"a module this controller does not know", "mystery"},
		{"a path instead of a filename", "jsonfrontend=../../etc/passwd"},
		{"a path with a separator", "jsonfrontend=sub/dir.json"},
		{"an empty filename", "jsonfrontend="},
		{"the same module twice", "healthz,healthz"},
		{"nothing but separators", ",,,"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.spec); err == nil {
				t.Errorf("Parse(%q) succeeded, want an error", tt.spec)
			}
		})
	}
}

func TestStatusFileFollowsTheModuleName(t *testing.T) {
	m, err := Parse("jsonfrontend=anything.json")
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	// The status file is named for the module, not for its configuration
	// file: that is what the service writes.
	if got := m[0].StatusFile(); got != "jsonfrontend.json" {
		t.Errorf("StatusFile = %q, want jsonfrontend.json", got)
	}
}
