// Package module names the forti services whose configuration forti-control
// manages, and the file each one reads.
//
// The table is hand-written and lives here rather than in forti, because the
// controller has no Go dependency on forti: it knows the filenames and nothing
// about what is inside them. A module the controller has never heard of is
// simply one nobody can edit from the UI; it is not broken.
package module

import (
	"errors"
	"fmt"
	"strings"
)

// A Module is one forti service with one configuration file.
type Module struct {
	// Name identifies the module in URLs, in the audit log, and in the
	// status file the service writes: /status/<Name>.json.
	Name string

	// File is the basename of the module's file in the config directory.
	// Deployments vary — rawdataforecaster is run once per product — so this
	// is what the service's -config flag points at, not a fixed convention.
	File string

	// Title and Summary are what the UI shows.
	Title   string
	Summary string

	// Reloads records whether the service watches its file. A service that
	// does not will never write a status file, and its changes take effect on
	// the next deploy; saying so is better than a status panel that waits
	// forever for an acknowledgement that is not coming.
	Reloads bool
}

// StatusFile is the name the module's service writes in the status directory.
func (m Module) StatusFile() string { return m.Name + ".json" }

// All is every module the controller manages, in display order.
//
// correctedforecaster is absent on purpose: it is configured entirely by
// flags and has no file to edit. xmlfrontend and moxfrontend are out of scope.
var All = []Module{
	{
		Name:    "jsonfrontend",
		File:    "jsonformat.json",
		Title:   "JSON frontend",
		Summary: "Parameter mapping, time periods and HTTP headers for the JSON API.",
		Reloads: true,
	},
	{
		Name:    "rawdataforecaster",
		File:    "nowcast.json",
		Title:   "Raw data forecaster",
		Summary: "Data source, areas and loader strategy.",
		Reloads: true,
	},
	{
		Name:    "healthz",
		File:    "probes.json",
		Title:   "Health probes",
		Summary: "Probe endpoints and the assertions made against them.",
		Reloads: false,
	},
}

// Parse builds a module list from a comma-separated deployment spec, where
// each entry is a name from All, optionally with the file that deployment
// gives it: "jsonfrontend,rawdataforecaster=forecast.json".
//
// The file has to be nameable because a deployment runs rawdataforecaster
// once per product — nowcast, forecast, oceanforecast — and each instance
// reads a different file. The name still has to be one this controller knows,
// so that nothing arriving from configuration can widen what the UI is able
// to write.
//
// An empty spec means All.
func Parse(spec string) ([]Module, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return All, nil
	}

	var modules []Module
	seen := map[string]bool{}

	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		name, file, named := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		file = strings.TrimSpace(file)

		m, err := find(name)
		if err != nil {
			return nil, err
		}
		if named {
			if file == "" || strings.ContainsAny(file, `/\`) {
				return nil, fmt.Errorf("%q is not a filename", file)
			}
			m.File = file
		}
		if seen[m.Name] {
			return nil, fmt.Errorf("%s named twice", m.Name)
		}

		seen[m.Name] = true
		modules = append(modules, m)
	}

	if len(modules) == 0 {
		return nil, errors.New("no modules named")
	}
	return modules, nil
}

func find(name string) (Module, error) {
	for _, m := range All {
		if m.Name == name {
			return m, nil
		}
	}
	return Module{}, fmt.Errorf("no module named %q", name)
}
