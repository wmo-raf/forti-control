package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/metno/forti-control/internal/configstore"
	"github.com/metno/forti-control/internal/module"
	"github.com/metno/forti-control/internal/status"
	"github.com/metno/forti-control/internal/store"
)

// page is what every template is given. One struct rather than one per
// screen: the fields a screen does not use stay zero, and a template that
// mentions a field the handler forgot renders empty instead of failing to
// compile against a type nobody reads.
type page struct {
	Title string
	User  store.User
	CSRF  string

	// Error and Notice are shown at the top of the page.
	Error  string
	Notice string

	// Problems is every reason a save was refused, following the convention
	// forti's own validators use: report all of them, not the first.
	Problems []string

	// Username survives a failed login, so a typo in the password does not
	// cost the username too.
	Username string

	Modules []moduleView

	Module  module.Module
	Content string

	// BaseSHA is the version the editor was opened on. It comes back with the
	// save so that a change made against a file somebody else has since
	// replaced can be refused rather than silently overwriting theirs.
	BaseSHA string
	Verdict status.Verdict
	History []snapshotView
	Audit   []store.Entry

	Snapshot     configstore.Snapshot
	SnapshotData string
}

// moduleView is one row of the module list.
type moduleView struct {
	Module  module.Module
	Verdict status.Verdict
}

// snapshotView is one row of a module's history. Current marks the version
// that is on disk now, which is the one there is no point restoring.
type snapshotView struct {
	Snapshot configstore.Snapshot
	Current  bool
	Live     bool
}

type templateSet struct {
	pages    map[string]*template.Template
	partials *template.Template
}

var pageNames = []string{"login.html", "modules.html", "module.html", "audit.html", "snapshot.html"}

func parseTemplates() (*templateSet, error) {
	set := &templateSet{pages: map[string]*template.Template{}}

	for _, name := range pageNames {
		t, err := template.New("base.html").Funcs(templateFuncs).ParseFS(assets,
			"templates/base.html",
			"templates/partials/*.html",
			"templates/pages/"+name,
		)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		set.pages[name] = t
	}

	partials, err := template.New("").Funcs(templateFuncs).ParseFS(assets, "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing partials: %w", err)
	}
	set.partials = partials
	return set, nil
}

// render writes a whole page with a 200.
func (s *Server) render(w http.ResponseWriter, name string, data page) {
	s.renderStatus(w, http.StatusOK, name, data)
}

// renderStatus writes a whole page with a given status code. It renders into
// a buffer first, so that a template that fails halfway does not leave a torn
// page behind a 200 — and so that the headers can still be set, which they
// cannot be once anything has been written.
func (s *Server) renderStatus(w http.ResponseWriter, code int, name string, data page) {
	t, ok := s.templates.pages[name]
	if !ok {
		s.fail(w, fmt.Errorf("no template named %s", name))
		return
	}

	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base.html", data); err != nil {
		s.fail(w, fmt.Errorf("rendering %s: %w", name, err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	buf.WriteTo(w)
}

// renderPartial writes one fragment, for htmx to swap into a page that is
// already loaded.
func (s *Server) renderPartial(w http.ResponseWriter, name string, data page) {
	var buf bytes.Buffer
	if err := s.templates.partials.ExecuteTemplate(&buf, name, data); err != nil {
		s.fail(w, fmt.Errorf("rendering partial %s: %w", name, err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

var templateFuncs = template.FuncMap{
	"short": configstore.Short,
	"stamp": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	// ago is what makes a status panel readable at a glance: "3s ago" says
	// the service is alive, "2 days ago" says it is not.
	"ago": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		d := time.Since(t)
		switch {
		case d < 0:
			return "just now"
		case d < time.Minute:
			return fmt.Sprintf("%ds ago", int(d.Seconds()))
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	},
}
