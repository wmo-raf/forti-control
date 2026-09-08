package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metno/forti-control/internal/configstore"
	"github.com/metno/forti-control/internal/module"
	"github.com/metno/forti-control/internal/status"
	"github.com/metno/forti-control/internal/store"
)

const (
	testUser     = "admin"
	testPassword = "a good long password"
)

var testModules = []module.Module{
	{Name: "jsonfrontend", File: "jsonformat.json", Title: "JSON frontend", Summary: "Parameter mapping.", Reloads: true},
	{Name: "healthz", File: "probes.json", Title: "Health probes", Summary: "Probe assertions.", Reloads: false},
}

type harness struct {
	t         *testing.T
	server    *httptest.Server
	client    *http.Client
	db        *store.DB
	configs   *configstore.Store
	configDir string
	statusDir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	statusDir := filepath.Join(root, "status")
	if err := os.MkdirAll(statusDir, 0o755); err != nil {
		t.Fatalf("creating the status directory: %s", err)
	}

	db, err := store.Open(filepath.Join(root, "control.db"))
	if err != nil {
		t.Fatalf("opening the database: %s", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.CreateUser(testUser, testPassword); err != nil {
		t.Fatalf("creating the test user: %s", err)
	}

	configs, err := configstore.New(configDir, filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatalf("opening the config store: %s", err)
	}

	srv, err := New(db, configs, &status.Reader{Dir: statusDir}, testModules, false)
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	httpServer := httptest.NewServer(srv)
	t.Cleanup(httpServer.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %s", err)
	}
	client := &http.Client{
		Jar: jar,
		// Redirects are part of what is under test, so they are not followed
		// by default; followRedirects turns them back on where a test wants
		// the page at the end.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return &harness{t: t, server: httpServer, client: client, db: db, configs: configs, configDir: configDir, statusDir: statusDir}
}

func (h *harness) get(path string, headers ...[2]string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest("GET", h.server.URL+path, nil)
	if err != nil {
		h.t.Fatalf("building a request for %s: %s", path, err)
	}
	for _, kv := range headers {
		req.Header.Set(kv[0], kv[1])
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %s", path, err)
	}
	return resp
}

func (h *harness) post(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.client.PostForm(h.server.URL+path, form)
	if err != nil {
		h.t.Fatalf("POST %s: %s", path, err)
	}
	return resp
}

// login signs in the way a browser does: it fetches the form for its token
// before submitting.
func (h *harness) login() {
	h.t.Helper()
	resp := h.submitLogin(testUser, testPassword)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login: status %d, want 303", resp.StatusCode)
	}
}

func (h *harness) submitLogin(name, password string) *http.Response {
	h.t.Helper()
	return h.post("/login", url.Values{
		"csrf":     {h.csrf("/login")},
		"username": {name},
		"password": {password},
	})
}

var (
	csrfPattern = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)
	basePattern = regexp.MustCompile(`name="base" value="([0-9a-f]*)"`)
)

// csrf reads a form token out of a rendered page, the way a browser would.
func (h *harness) csrf(path string) string {
	h.t.Helper()
	return h.field(path, csrfPattern, "csrf")
}

// base reads the digest the editor was rendered on, which a browser sends
// back with the save.
func (h *harness) base(moduleName string) string {
	h.t.Helper()
	return h.field("/modules/"+moduleName, basePattern, "base")
}

func (h *harness) field(path string, pattern *regexp.Regexp, name string) string {
	h.t.Helper()
	resp := h.get(path)
	defer resp.Body.Close()

	match := pattern.FindStringSubmatch(read(h.t, resp))
	if match == nil {
		h.t.Fatalf("no %s field on %s", name, path)
	}
	return match[1]
}

// save posts the editor the way a browser does: with the token and the digest
// the page was rendered on.
func (h *harness) save(moduleName, content string) *http.Response {
	h.t.Helper()
	return h.post("/modules/"+moduleName, url.Values{
		"csrf":    {h.csrf("/modules/" + moduleName)},
		"base":    {h.base(moduleName)},
		"content": {content},
	})
}

// report writes a status file as a running service would.
func (h *harness) report(s status.Status) {
	h.t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		h.t.Fatalf("marshalling a status: %s", err)
	}
	if err := os.WriteFile(filepath.Join(h.statusDir, s.Module+".json"), data, 0o644); err != nil {
		h.t.Fatalf("writing a status file: %s", err)
	}
}

func (h *harness) liveFile(moduleName string) string {
	h.t.Helper()
	for _, m := range testModules {
		if m.Name != moduleName {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.configDir, m.File))
		if err != nil {
			return ""
		}
		return string(data)
	}
	h.t.Fatalf("no test module named %s", moduleName)
	return ""
}

func read(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response body: %s", err)
	}
	return string(body)
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSignedOutVisitorsAreSentToTheLoginPage(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/", "/modules/jsonfrontend", "/audit", "/modules/jsonfrontend/status"} {
		t.Run(path, func(t *testing.T) {
			resp := h.get(path)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("status %d, want 303", resp.StatusCode)
			}
			if got := resp.Header.Get("Location"); got != "/login" {
				t.Errorf("Location = %q, want /login", got)
			}
		})
	}
}

// A polling status panel outliving its session must move the browser to the
// login page, not paste a login form into the middle of the editor.
func TestAnExpiredSessionRedirectsTheWholeHTMXPage(t *testing.T) {
	h := newHarness(t)

	resp := h.get("/modules/jsonfrontend/status", [2]string{"HX-Request", "true"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("HX-Redirect"); got != "/login" {
		t.Errorf("HX-Redirect = %q, want /login", got)
	}
}

func TestLoginRejectsTheWrongPassword(t *testing.T) {
	h := newHarness(t)

	resp := h.submitLogin(testUser, "not it")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	if body := read(t, resp); !strings.Contains(body, "do not match") {
		t.Error("the login page does not say the credentials were wrong")
	}
}

func TestLoginLetsTheUserSeeTheModules(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.get("/")
	defer resp.Body.Close()
	body := read(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	for _, m := range testModules {
		if !strings.Contains(body, m.Title) {
			t.Errorf("the module list does not mention %q", m.Title)
		}
		if !strings.Contains(body, m.File) {
			t.Errorf("the module list does not mention %q", m.File)
		}
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.post("/logout", url.Values{"csrf": {h.csrf("/")}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: status %d, want 303", resp.StatusCode)
	}

	after := h.get("/")
	defer after.Body.Close()
	if after.StatusCode != http.StatusSeeOther {
		t.Errorf("status %d after signing out, want a redirect to the login page", after.StatusCode)
	}
}

func TestSaveWritesTheFile(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"offer_gzip": true}`

	resp := h.save("jsonfrontend", content)
	defer resp.Body.Close()
	body := read(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Saved") {
		t.Errorf("the save result does not say it saved: %q", body)
	}
	if got := h.liveFile("jsonfrontend"); got != content+"\n" {
		t.Errorf("the file on disk = %q, want %q", got, content+"\n")
	}
}

func TestSaveRecordsAnAuditEntryLinkedToASnapshot(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"a": 1}`

	resp := h.save("jsonfrontend", content)
	resp.Body.Close()

	entries, err := h.db.Audit("jsonfrontend", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	got := entries[0]
	if got.Action != store.ActionSave {
		t.Errorf("Action = %q, want %q", got.Action, store.ActionSave)
	}
	if got.User != testUser {
		t.Errorf("User = %q, want %q", got.User, testUser)
	}
	if want := sha(content + "\n"); got.SnapshotSHA != want {
		t.Errorf("SnapshotSHA = %q, want %q", got.SnapshotSHA, want)
	}

	// The linkage has to lead to the bytes, not just name them.
	stored, err := h.configs.SnapshotData(testModules[0], got.SnapshotSHA)
	if err != nil {
		t.Fatalf("following the audit entry to its snapshot: %s", err)
	}
	if string(stored) != content+"\n" {
		t.Errorf("the snapshot holds %q, want %q", stored, content+"\n")
	}
}

func TestASecondSaveRecordsWhatItReplaced(t *testing.T) {
	h := newHarness(t)
	h.login()

	first := h.save("jsonfrontend", `{"v": 1}`)
	first.Body.Close()
	second := h.save("jsonfrontend", `{"v": 2}`)
	second.Body.Close()

	entries, err := h.db.Audit("jsonfrontend", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d audit entries, want 2", len(entries))
	}
	if want := sha(`{"v": 1}` + "\n"); entries[0].PreviousSHA != want {
		t.Errorf("PreviousSHA = %q, want the first version's digest %q", entries[0].PreviousSHA, want)
	}
}

// The controller's own refusal: what was submitted is not JSON, so nothing is
// written and the service never sees it.
func TestSavingSomethingThatIsNotJSONWritesNothing(t *testing.T) {
	h := newHarness(t)
	h.login()
	const good = `{"good": true}`
	h.save("jsonfrontend", good).Body.Close()

	resp := h.save("jsonfrontend", "{\n  \"broken\": \n}")
	defer resp.Body.Close()
	body := read(t, resp)

	if !strings.Contains(body, "Not saved") {
		t.Errorf("the save result does not say it refused: %q", body)
	}
	if !strings.Contains(body, "line 3") {
		t.Errorf("the save result does not say where the problem is: %q", body)
	}
	if got := h.liveFile("jsonfrontend"); got != good+"\n" {
		t.Errorf("the file on disk = %q; the previous version should be untouched", got)
	}
}

func TestARefusedSaveIsStillRecorded(t *testing.T) {
	h := newHarness(t)
	h.login()

	h.save("jsonfrontend", "not json").Body.Close()

	entries, err := h.db.Audit("jsonfrontend", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Action != store.ActionRejected {
		t.Errorf("Action = %q, want %q", entries[0].Action, store.ActionRejected)
	}
	if entries[0].SnapshotSHA != "" {
		t.Error("a refused save recorded a snapshot; nothing was written")
	}
}

func TestSaveWithoutACSRFTokenIsRefused(t *testing.T) {
	h := newHarness(t)
	h.login()

	for name, form := range map[string]url.Values{
		"no token":    {"content": {`{"a":1}`}},
		"wrong token": {"csrf": {"0000"}, "content": {`{"a":1}`}},
	} {
		t.Run(name, func(t *testing.T) {
			resp := h.post("/modules/jsonfrontend", form)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status %d, want 403", resp.StatusCode)
			}
			if h.liveFile("jsonfrontend") != "" {
				t.Error("a request without a valid token wrote the file")
			}
		})
	}
}

func TestSavingToAnUnknownModuleIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.post("/modules/../../etc/passwd", url.Values{"csrf": {h.csrf("/")}, "content": {`{}`}})
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Errorf("status %d; a module outside the registry must not be writable", resp.StatusCode)
	}
}

// This is the case the whole slice exists to make visible: the file was
// written, the service read it and would not have it, and the UI has to say
// so while the service carries on with what it had.
func TestTheStatusPanelReportsAConfigurationTheServiceRefused(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"periods": "two of these share an offset"}`
	h.save("jsonfrontend", content).Body.Close()

	h.report(status.Status{
		Module:    "jsonfrontend",
		LoadedSHA: sha(content + "\n"),
		LoadedAt:  time.Now().UTC(),
		OK:        false,
		Errors:    []string{"two time periods share offset 0"},
	})

	resp := h.get("/modules/jsonfrontend/status")
	defer resp.Body.Close()
	body := read(t, resp)

	if !strings.Contains(body, "Rejected") {
		t.Error("the status panel does not say the configuration was rejected")
	}
	if !strings.Contains(body, "two time periods share offset 0") {
		t.Error("the status panel does not show the service's reason")
	}
	if !strings.Contains(body, "not using the file on disk") {
		t.Error("the status panel does not say the service is still on the previous configuration")
	}
}

func TestTheStatusPanelReportsAConfigurationThatWentLive(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"offer_gzip": true}`
	h.save("jsonfrontend", content).Body.Close()

	h.report(status.Status{
		Module:    "jsonfrontend",
		LoadedSHA: sha(content + "\n"),
		LoadedAt:  time.Now().UTC(),
		OK:        true,
		Applied:   []string{"parameters", "http_headers"},
	})

	resp := h.get("/modules/jsonfrontend/status")
	defer resp.Body.Close()
	body := read(t, resp)

	if !strings.Contains(body, "Live") {
		t.Error("the status panel does not say the configuration is live")
	}
	if strings.Contains(body, "not using the file on disk") {
		t.Error("the status panel warns about an older configuration for one that went live")
	}
	if !strings.Contains(body, "http_headers") {
		t.Error("the status panel does not list what was applied")
	}
}

// A service reporting happily about the version before the one just saved is
// not a service that accepted the save.
func TestTheStatusPanelDoesNotCallAStaleAcknowledgementLive(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()
	h.report(status.Status{
		Module:    "jsonfrontend",
		LoadedSHA: sha(`{"v": 1}` + "\n"),
		LoadedAt:  time.Now().UTC(),
		OK:        true,
	})
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	resp := h.get("/modules/jsonfrontend/status")
	defer resp.Body.Close()
	body := read(t, resp)

	if strings.Contains(body, ">Live<") {
		t.Error("the status panel called an acknowledgement of the previous version live")
	}
	if !strings.Contains(body, "Waiting") {
		t.Errorf("the status panel does not say it is waiting: %q", body)
	}
}

func TestAModuleThatDoesNotReloadSaysSo(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("healthz", `{"probes": []}`).Body.Close()

	resp := h.get("/modules/healthz/status")
	defer resp.Body.Close()

	if body := read(t, resp); !strings.Contains(body, "next deploy") {
		t.Errorf("the status panel does not say the change waits for a deploy: %q", body)
	}
}

func TestSaveAsksThePageToRefreshItsStatus(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.save("jsonfrontend", `{"a": 1}`)
	defer resp.Body.Close()

	if got := resp.Header.Get("HX-Trigger"); got != "config-saved" {
		t.Errorf("HX-Trigger = %q, want config-saved", got)
	}
}

func TestRestoreWritesAnOldVersionBack(t *testing.T) {
	h := newHarness(t)
	h.login()
	const first = `{"v": 1}`
	h.save("jsonfrontend", first).Body.Close()
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	resp := h.post("/modules/jsonfrontend/restore", url.Values{
		"csrf": {h.csrf("/modules/jsonfrontend")},
		"sha":  {sha(first + "\n")},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", resp.StatusCode)
	}
	if got := h.liveFile("jsonfrontend"); got != first+"\n" {
		t.Errorf("the file on disk = %q, want the first version %q", got, first+"\n")
	}

	entries, err := h.db.Audit("jsonfrontend", 10)
	if err != nil {
		t.Fatalf("Audit: %s", err)
	}
	if entries[0].Action != store.ActionRestore {
		t.Errorf("Action = %q, want %q", entries[0].Action, store.ActionRestore)
	}
	if want := sha(`{"v": 2}` + "\n"); entries[0].PreviousSHA != want {
		t.Errorf("PreviousSHA = %q, want the version it replaced", entries[0].PreviousSHA)
	}
}

// A restore is itself undoable: it must not throw away the version it
// replaced.
func TestRestoreKeepsTheVersionItReplaced(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	h.post("/modules/jsonfrontend/restore", url.Values{
		"csrf": {h.csrf("/modules/jsonfrontend")},
		"sha":  {sha(`{"v": 1}` + "\n")},
	}).Body.Close()

	history, err := h.configs.History(testModules[0])
	if err != nil {
		t.Fatalf("History: %s", err)
	}
	if len(history) != 2 {
		t.Fatalf("history has %d versions, want both", len(history))
	}
}

func TestRestoreRejectsASnapshotThatIsNotThere(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()

	resp := h.post("/modules/jsonfrontend/restore", url.Values{
		"csrf": {h.csrf("/modules/jsonfrontend")},
		"sha":  {"../../../etc/passwd"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
	if got := h.liveFile("jsonfrontend"); got != `{"v": 1}`+"\n" {
		t.Errorf("the file on disk changed to %q", got)
	}
}

func TestTheEditorShowsWhatIsOnDisk(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"location_from_grid": true}`
	h.save("jsonfrontend", content).Body.Close()

	resp := h.get("/modules/jsonfrontend")
	defer resp.Body.Close()
	body := read(t, resp)

	if !strings.Contains(body, "location_from_grid") {
		t.Error("the editor does not contain the saved configuration")
	}
}

func TestASnapshotCanBeRead(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"only": "in the snapshot"}`
	h.save("jsonfrontend", content).Body.Close()
	h.save("jsonfrontend", `{"now": "something else"}`).Body.Close()

	resp := h.get("/modules/jsonfrontend/snapshots/" + sha(content+"\n"))
	defer resp.Body.Close()
	body := read(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "only") {
		t.Error("the snapshot page does not show the snapshot's contents")
	}
}

// Windows line endings from a browser must not make every save through the UI
// differ from the same file written by hand.
func TestSaveNormalizesLineEndings(t *testing.T) {
	h := newHarness(t)
	h.login()

	h.save("jsonfrontend", "{\r\n  \"a\": 1\r\n}").Body.Close()

	if got := h.liveFile("jsonfrontend"); got != "{\n  \"a\": 1\n}\n" {
		t.Errorf("the file on disk = %q, want LF endings and a trailing newline", got)
	}
}

func TestTheActivityPageListsEveryModule(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"a": 1}`).Body.Close()
	h.save("healthz", `{"b": 2}`).Body.Close()

	resp := h.get("/audit")
	defer resp.Body.Close()
	body := read(t, resp)

	for _, name := range []string{"jsonfrontend", "healthz"} {
		if !strings.Contains(body, name) {
			t.Errorf("the activity page does not mention %s", name)
		}
	}
}

func TestHealthzNeedsNoLogin(t *testing.T) {
	h := newHarness(t)

	resp := h.get("/healthz")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
}

// The status panel polls, so it must not carry the restore controls: a poll
// that replaced them would close the confirmation under whoever was reading
// it.
func TestThePolledStatusPanelCarriesNoRestoreControls(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	resp := h.get("/modules/jsonfrontend/status")
	defer resp.Body.Close()

	if body := read(t, resp); strings.Contains(body, "/restore") {
		t.Error("the polled status panel contains the restore form")
	}
}

func TestTheHistoryPanelOffersRestoreForEveryVersionButTheCurrentOne(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	resp := h.get("/modules/jsonfrontend/history")
	defer resp.Body.Close()
	body := read(t, resp)

	if got := strings.Count(body, `action="/modules/jsonfrontend/restore"`); got != 1 {
		t.Errorf("found %d restore forms, want 1 — one per version except the one on disk", got)
	}
	if !strings.Contains(body, sha(`{"v": 1}`+"\n")) {
		t.Error("the history panel does not offer the older version")
	}
	if !strings.Contains(body, "on disk") {
		t.Error("the history panel does not mark which version is on disk")
	}
}

// The history panel refreshes when a save happens rather than on a timer.
func TestTheHistoryPanelDoesNotPoll(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()

	resp := h.get("/modules/jsonfrontend/history")
	defer resp.Body.Close()
	body := read(t, resp)

	if strings.Contains(body, "every ") {
		t.Error("the history panel has a polling trigger")
	}
	if !strings.Contains(body, "config-saved") {
		t.Error("the history panel does not refresh when a save happens")
	}
}

// The digest in the status panel is what the service last read. Describing a
// refused version as the one being served would contradict the verdict
// printed directly above it.
func TestTheStatusPanelDoesNotCallARefusedVersionTheOneBeingServed(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"bad": true}`
	h.save("jsonfrontend", content).Body.Close()
	h.report(status.Status{
		Module:    "jsonfrontend",
		LoadedSHA: sha(content + "\n"),
		LoadedAt:  time.Now().UTC(),
		OK:        false,
		Errors:    []string{"no"},
	})

	resp := h.get("/modules/jsonfrontend/status")
	defer resp.Body.Close()
	body := read(t, resp)

	if strings.Contains(body, "Serving") {
		t.Error("the status panel says it is serving a configuration the service refused")
	}
	if !strings.Contains(body, "Last read") {
		t.Errorf("the status panel does not say the digest is what was last read: %q", body)
	}
}

func TestALiveConfigurationIsDescribedAsServed(t *testing.T) {
	h := newHarness(t)
	h.login()
	const content = `{"good": true}`
	h.save("jsonfrontend", content).Body.Close()
	h.report(status.Status{
		Module:    "jsonfrontend",
		LoadedSHA: sha(content + "\n"),
		LoadedAt:  time.Now().UTC(),
		OK:        true,
	})

	resp := h.get("/modules/jsonfrontend/status")
	defer resp.Body.Close()

	if body := read(t, resp); !strings.Contains(body, "Serving") {
		t.Error("the status panel does not say a live configuration is being served")
	}
}

// Two people editing the same file: the second save is made against a version
// that is no longer there, and writing it would drop the first person's change
// with nobody told. That is this codebase's own bug pattern, so the controller
// must not commit it.
func TestASaveMadeAgainstAVersionThatHasMovedIsRefused(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()

	// One tab opens the editor.
	stale := h.base("jsonfrontend")
	csrf := h.csrf("/modules/jsonfrontend")

	// Another saves before the first one does.
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	resp := h.post("/modules/jsonfrontend", url.Values{
		"csrf":    {csrf},
		"base":    {stale},
		"content": {`{"v": 3}`},
	})
	defer resp.Body.Close()
	body := read(t, resp)

	if !strings.Contains(body, "changed since you opened it") {
		t.Errorf("the save result does not explain the conflict: %q", body)
	}
	if got := h.liveFile("jsonfrontend"); got != `{"v": 2}`+"\n" {
		t.Errorf("the file on disk = %q; the other person's save should still be there", got)
	}
}

func TestASaveAgainstTheCurrentVersionGoesThrough(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()

	resp := h.save("jsonfrontend", `{"v": 2}`)
	defer resp.Body.Close()

	if body := read(t, resp); !strings.Contains(body, "Saved") {
		t.Errorf("a save against the current version was refused: %q", body)
	}
}

// Creating a file that does not exist yet is a save against nothing.
func TestTheFirstSaveOfAModuleNeedsNoBaseVersion(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.save("jsonfrontend", `{"v": 1}`)
	defer resp.Body.Close()

	if body := read(t, resp); !strings.Contains(body, "Saved") {
		t.Errorf("the first save of a module was refused: %q", body)
	}
}

// Without this another site can make a signed-out browser post to /login and
// pin whoever is using it to an account the attacker controls.
func TestLoginWithoutItsFormTokenIsRefused(t *testing.T) {
	h := newHarness(t)

	resp := h.post("/login", url.Values{"username": {testUser}, "password": {testPassword}})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	if after := h.get("/"); after.StatusCode != http.StatusSeeOther {
		after.Body.Close()
		t.Error("the request signed somebody in anyway")
	} else {
		after.Body.Close()
	}
}

// Guessing has to be slow against a service that edits production config.
func TestRepeatedWrongPasswordsStopBeingAnswered(t *testing.T) {
	h := newHarness(t)

	var last *http.Response
	for range loginAttempts {
		last = h.submitLogin(testUser, "wrong")
		last.Body.Close()
		if last.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d during the allowed attempts, want 401", last.StatusCode)
		}
	}

	blocked := h.submitLogin(testUser, "wrong")
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status %d after %d failures, want 429", blocked.StatusCode, loginAttempts)
	}

	// And the throttle must hold even for the right password, or it is no
	// throttle at all.
	right := h.submitLogin(testUser, testPassword)
	defer right.Body.Close()
	if right.StatusCode == http.StatusSeeOther {
		t.Error("a blocked account signed in with the right password")
	}
}

func TestASuccessfulLoginForgetsEarlierFailures(t *testing.T) {
	h := newHarness(t)

	for range loginAttempts - 1 {
		h.submitLogin(testUser, "wrong").Body.Close()
	}
	h.login()
	// Signed in, the login page only redirects, so step back out of it.
	h.post("/logout", url.Values{"csrf": {h.csrf("/")}}).Body.Close()

	for range loginAttempts - 1 {
		resp := h.submitLogin(testUser, "wrong")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatal("the failures before a successful sign-in still counted")
		}
	}
}

func TestEveryPageCarriesItsSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.get("/modules/jsonfrontend")
	defer resp.Body.Close()

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q", got)
	}
}

// A page rendered with an error status still has to be typed, or a browser
// sniffs it.
func TestAFailedLoginIsStillLabelledHTML(t *testing.T) {
	h := newHarness(t)

	resp := h.submitLogin(testUser, "not it")
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
}

// A tab that saves is then open on the version it wrote. If the save result
// did not move the editor's base digest with it, that tab's next save would
// be refused as a conflict with itself.
func TestASaveMovesTheEditorOntoTheVersionItWrote(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.save("jsonfrontend", `{"v": 1}`)
	defer resp.Body.Close()
	body := read(t, resp)

	want := sha(`{"v": 1}` + "\n")
	if !strings.Contains(body, `id="base"`) || !strings.Contains(body, want) {
		t.Fatalf("the save result does not carry the new base digest: %q", body)
	}
	if !strings.Contains(body, `hx-swap-oob="true"`) {
		t.Error("the new base digest is not swapped into the page")
	}
}

// Two saves in a row from the same tab, using only what the save result gives
// back — the sequence a browser actually performs.
func TestConsecutiveSavesFromOneTabBothSucceed(t *testing.T) {
	h := newHarness(t)
	h.login()
	csrf := h.csrf("/modules/jsonfrontend")

	first := h.post("/modules/jsonfrontend", url.Values{
		"csrf": {csrf}, "base": {h.base("jsonfrontend")}, "content": {`{"v": 1}`},
	})
	defer first.Body.Close()
	if body := read(t, first); !strings.Contains(body, "Saved") {
		t.Fatalf("the first save was refused: %q", body)
	}

	// The base the page now holds is the one the first save handed back.
	second := h.post("/modules/jsonfrontend", url.Values{
		"csrf": {csrf}, "base": {sha(`{"v": 1}` + "\n")}, "content": {`{"v": 2}`},
	})
	defer second.Body.Close()
	if body := read(t, second); !strings.Contains(body, "Saved") {
		t.Errorf("the second save from the same tab was refused: %q", body)
	}
	if got := h.liveFile("jsonfrontend"); got != `{"v": 2}`+"\n" {
		t.Errorf("the file on disk = %q, want the second version", got)
	}
}

// A refused save must NOT move the editor on, or reloading stops being
// necessary and the other person's change gets clobbered on the retry.
func TestARefusedSaveLeavesTheEditorWhereItWas(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.save("jsonfrontend", `{"v": 1}`).Body.Close()
	stale := h.base("jsonfrontend")
	csrf := h.csrf("/modules/jsonfrontend")
	h.save("jsonfrontend", `{"v": 2}`).Body.Close()

	resp := h.post("/modules/jsonfrontend", url.Values{
		"csrf": {csrf}, "base": {stale}, "content": {`{"v": 3}`},
	})
	defer resp.Body.Close()

	if body := read(t, resp); strings.Contains(body, `hx-swap-oob`) {
		t.Error("a refused save moved the editor onto a version it did not write")
	}
}
