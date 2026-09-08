// Command forti-control is a web UI for forti's configuration files.
//
// It writes files onto a shared volume and reads status files back off it.
// That is the whole interface: there is no connection to any forti service, no
// service discovery, no Docker socket, and no credentials for anything. A
// service picks up a change because it is watching its own file, and says what
// it made of it by writing a status file.
//
// Two directories on the volume matter:
//
//	-config-dir   the files the services read. The controller writes here.
//	-status-dir   what the services report. The controller only reads here.
//
// Keeping them apart is what lets a deployment mount the config directory
// read-only into the services while still giving them somewhere to write.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/metno/forti-control/internal/configstore"
	"github.com/metno/forti-control/internal/module"
	"github.com/metno/forti-control/internal/status"
	"github.com/metno/forti-control/internal/store"
	"github.com/metno/forti-control/internal/web"
)

func main() {
	listen := flag.String("listen", ":8081", "HTTP listen address")
	configDir := flag.String("config-dir", "/config", "Directory holding the configuration files the services read")
	statusDir := flag.String("status-dir", "/status", "Directory the services write their reload status to")
	dataDir := flag.String("data-dir", "/data", "Directory for the controller's own database and its snapshots of past configurations")
	adminUser := flag.String("admin-user", "admin", "Name of the administrator seeded on first start")
	modules := flag.String("modules", "", "Modules to manage, and the file each one reads: \"jsonfrontend,rawdataforecaster=forecast.json\" (empty for all of them, with their usual filenames)")
	secureCookie := flag.Bool("secure-cookie", false, "Only send the session cookie over HTTPS (set this when the controller is behind TLS)")
	flag.Parse()

	if err := run(options{
		listen:       *listen,
		configDir:    *configDir,
		statusDir:    *statusDir,
		dataDir:      *dataDir,
		adminUser:    *adminUser,
		modules:      *modules,
		secureCookie: *secureCookie,
	}); err != nil {
		log.Fatalf("forti-control: %s", err)
	}
}

type options struct {
	listen       string
	configDir    string
	statusDir    string
	dataDir      string
	adminUser    string
	modules      string
	secureCookie bool
}

func run(opts options) error {
	managed, err := module.Parse(opts.modules)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(opts.dataDir, 0o755); err != nil {
		return err
	}

	db, err := store.Open(filepath.Join(opts.dataDir, "control.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	if err := seedAdmin(db, opts.adminUser); err != nil {
		return err
	}

	configs, err := configstore.New(opts.configDir, filepath.Join(opts.dataDir, "snapshots"))
	if err != nil {
		return err
	}

	// Whatever is on the volume now is a version somebody may want back, and
	// it is the one version the controller can never reconstruct once it has
	// been overwritten. Record it before anybody can save over it.
	baseline, err := configs.Baseline(managed)
	if err != nil {
		return err
	}
	for _, snap := range baseline {
		log.Printf("recorded the existing %s configuration as %s", snap.Module, snap.Short())
		if err := db.Record(store.Entry{
			User:         "system",
			Module:       snap.Module,
			Action:       store.ActionBaseline,
			SnapshotSHA:  snap.SHA,
			SnapshotName: snap.Name,
			Note:         "the configuration found on the volume at startup",
		}); err != nil {
			return err
		}
	}

	server, err := web.New(db, configs, &status.Reader{Dir: opts.statusDir}, managed, opts.secureCookie)
	if err != nil {
		return err
	}

	go expireSessions(db)

	for _, m := range managed {
		log.Printf("managing %s from %s", m.Name, m.File)
	}
	log.Printf("config %s, status %s, data %s", opts.configDir, opts.statusDir, opts.dataDir)
	log.Printf("forti-control listening on %s", opts.listen)

	httpServer := &http.Server{
		Addr:    opts.listen,
		Handler: server,
		// A config file is small and a browser is close by; nothing here
		// should take anywhere near this long.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	return httpServer.ListenAndServe()
}

// seedAdmin creates the first administrator, once. The password comes from
// FORTI_CONTROL_ADMIN_PASSWORD, or is generated and printed if that is unset —
// printed rather than defaulted, because a default password on a service that
// edits production configuration is not a convenience.
func seedAdmin(db *store.DB, name string) error {
	password := os.Getenv("FORTI_CONTROL_ADMIN_PASSWORD")
	generated := password == ""
	if generated {
		var err error
		if password, err = randomPassword(); err != nil {
			return err
		}
	}

	created, err := db.SeedAdmin(name, password)
	if err != nil {
		return err
	}
	if created && generated {
		log.Printf("created the %q user with a generated password: %s", name, password)
		log.Printf("this is printed once. Set FORTI_CONTROL_ADMIN_PASSWORD to choose it yourself.")
	} else if created {
		log.Printf("created the %q user with the password from FORTI_CONTROL_ADMIN_PASSWORD", name)
	}
	return nil
}

func randomPassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// expireSessions clears out sessions nobody can use any more, so that the
// table does not grow forever in a service that runs for months.
func expireSessions(db *store.DB) {
	for range time.Tick(time.Hour) {
		if err := db.DeleteExpiredSessions(); err != nil {
			log.Printf("clearing expired sessions: %s", err)
		}
	}
}
