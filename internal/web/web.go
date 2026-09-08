// Package web is forti-control's user interface: server-rendered HTML with
// htmx for the parts that update on their own, all of it embedded in the
// binary so that the controller is one file to deploy.
//
// The interesting screen is the module editor. It has to make one distinction
// that nothing else in forti makes: between a configuration that was saved and
// a configuration that is being served. Those are the same thing only when a
// service has read the file and accepted it, and the point of the status panel
// is to say which of the two you are looking at.
package web

import (
	"embed"
	"log"
	"net/http"
	"time"

	"github.com/metno/forti-control/internal/configstore"
	"github.com/metno/forti-control/internal/module"
	"github.com/metno/forti-control/internal/status"
	"github.com/metno/forti-control/internal/store"
)

//go:embed templates static
var assets embed.FS

// SessionLifetime is how long a login lasts. Long enough for a working day.
const SessionLifetime = 12 * time.Hour

// A Server serves the whole UI.
type Server struct {
	DB      *store.DB
	Configs *configstore.Store
	Status  *status.Reader
	Modules []module.Module

	// Secure marks the session cookie secure. It is off by default because
	// the controller is usually reached over plain HTTP inside a deployment,
	// and a cookie that is never sent is worse than one that is.
	Secure bool

	csrfKey   []byte
	throttle  *throttle
	templates *templateSet
	mux       *http.ServeMux
}

// New builds a server and its routes.
func New(db *store.DB, configs *configstore.Store, statusReader *status.Reader, modules []module.Module, secure bool) (*Server, error) {
	csrfKey, err := db.SecretKey("csrf-key")
	if err != nil {
		return nil, err
	}

	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	s := &Server{
		DB:        db,
		Configs:   configs,
		Status:    statusReader,
		Modules:   modules,
		Secure:    secure,
		csrfKey:   csrfKey,
		throttle:  newThrottle(),
		templates: templates,
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /login", s.showLogin)
	mux.HandleFunc("POST /login", s.doLogin)
	mux.HandleFunc("POST /logout", s.requireUser(s.doLogout))

	mux.HandleFunc("GET /{$}", s.requireUser(s.showModules))
	mux.HandleFunc("GET /modules/{name}", s.requireUser(s.showModule))
	mux.HandleFunc("POST /modules/{name}", s.requireUser(s.saveModule))
	mux.HandleFunc("GET /modules/{name}/status", s.requireUser(s.showStatus))
	mux.HandleFunc("GET /modules/{name}/history", s.requireUser(s.showHistory))
	mux.HandleFunc("POST /modules/{name}/restore", s.requireUser(s.restoreModule))
	mux.HandleFunc("GET /modules/{name}/snapshots/{sha}", s.requireUser(s.showSnapshot))
	mux.HandleFunc("GET /audit", s.requireUser(s.showAudit))

	s.mux = mux
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	secureHeaders(s.mux).ServeHTTP(w, r)
}

// module resolves the module named in the path, writing a 404 if there is no
// such module. The registry is the allow-list: a name from a URL never
// reaches the filesystem as anything but a Module that was already known.
func (s *Server) module(w http.ResponseWriter, r *http.Request) (module.Module, bool) {
	name := r.PathValue("name")
	for _, m := range s.Modules {
		if m.Name == name {
			return m, true
		}
	}
	http.Error(w, "no such module", http.StatusNotFound)
	return module.Module{}, false
}

// verdict is the current answer to "is what is saved what is being served?"
// for one module.
func (s *Server) verdict(m module.Module) (status.Verdict, configstore.Content, error) {
	content, err := s.Configs.Read(m)
	if err != nil {
		return status.Verdict{}, content, err
	}

	reported, err := s.Status.Read(m)
	if err != nil {
		// An unreadable status file says nothing about the configuration, and
		// must not stop the page that would let somebody fix it.
		log.Printf("status for %s: %s", m.Name, err)
		reported = nil
	}

	file := status.File{SHA: content.SHA, ModTime: content.ModTime, Exists: content.Exists}
	return status.Evaluate(m, file, reported, time.Now().UTC()), content, nil
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	log.Printf("forti-control: %s", err)
	http.Error(w, "something went wrong; see the controller's log", http.StatusInternalServerError)
}
