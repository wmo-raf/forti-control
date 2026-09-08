package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/metno/forti-control/internal/configstore"
	"github.com/metno/forti-control/internal/module"
	"github.com/metno/forti-control/internal/status"
	"github.com/metno/forti-control/internal/store"
)

// historyLimit is how many past versions and audit entries a module page
// shows. Enough to find last week's change without paginating.
const historyLimit = 25

func (s *Server) showModules(w http.ResponseWriter, r *http.Request, user store.User) {
	views := make([]moduleView, 0, len(s.Modules))
	for _, m := range s.Modules {
		verdict, _, err := s.verdict(m)
		if err != nil {
			s.fail(w, err)
			return
		}
		views = append(views, moduleView{Module: m, Verdict: verdict})
	}

	s.render(w, "modules.html", page{
		Title:   "Modules",
		User:    user,
		CSRF:    s.csrfFor(r),
		Modules: views,
	})
}

func (s *Server) showModule(w http.ResponseWriter, r *http.Request, user store.User) {
	m, ok := s.module(w, r)
	if !ok {
		return
	}

	data, content, err := s.modulePage(m, user, r)
	if err != nil {
		s.fail(w, err)
		return
	}
	data.Content = string(content.Data)
	data.BaseSHA = content.SHA
	data.Notice = r.URL.Query().Get("notice")

	s.render(w, "module.html", data)
}

// modulePage assembles everything the module screen shows except the editor's
// contents: the verdict, the history, and the recent activity. It returns the
// live file alongside, so that the caller rendering the editor does not have
// to read it a second time.
func (s *Server) modulePage(m module.Module, user store.User, r *http.Request) (page, configstore.Content, error) {
	verdict, content, err := s.verdict(m)
	if err != nil {
		return page{}, content, err
	}

	history, err := s.Configs.History(m)
	if err != nil {
		return page{}, content, err
	}
	views := make([]snapshotView, 0, len(history))
	for i, snap := range history {
		if i >= historyLimit {
			break
		}
		views = append(views, snapshotView{
			Snapshot: snap,
			Current:  snap.SHA == content.SHA,
			Live:     snap.SHA == verdict.LoadedSHA && verdict.State == status.StateLive,
		})
	}

	audit, err := s.DB.Audit(m.Name, historyLimit)
	if err != nil {
		return page{}, content, err
	}

	return page{
		Title:   m.Title,
		User:    user,
		CSRF:    s.csrfFor(r),
		Module:  m,
		Verdict: verdict,
		History: views,
		Audit:   audit,
	}, content, nil
}

// showStatus renders the status panel on its own. It is what the page polls,
// because the verdict is the only part of the screen that changes without
// anybody doing anything: a service picks the file up a second after a save.
func (s *Server) showStatus(w http.ResponseWriter, r *http.Request, _ store.User) {
	m, ok := s.module(w, r)
	if !ok {
		return
	}

	verdict, _, err := s.verdict(m)
	if err != nil {
		s.fail(w, err)
		return
	}

	// Deliberately not the whole module page: this runs once a second per
	// open tab, and the history and the audit log cannot change without a
	// save, which refreshes them by itself.
	s.renderPartial(w, "statuspanel.html", page{Module: m, Verdict: verdict})
}

// showHistory renders the history and activity panels. They change only when
// somebody saves, so they refresh on a save rather than on a timer — a timer
// would close the restore confirmation under the reader every few seconds.
func (s *Server) showHistory(w http.ResponseWriter, r *http.Request, user store.User) {
	s.renderModulePartial(w, r, user, "historypanel.html")
}

func (s *Server) renderModulePartial(w http.ResponseWriter, r *http.Request, user store.User, name string) {
	m, ok := s.module(w, r)
	if !ok {
		return
	}

	data, _, err := s.modulePage(m, user, r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderPartial(w, name, data)
}

// saveModule writes what was typed into the editor.
//
// The controller checks that the submission is JSON and nothing more. Whether
// the contents mean anything is the service's judgement — it has the schema,
// the controller does not — and the answer comes back through the status file
// a second later. So a save that succeeds here is only a save: the panel next
// to the editor is what says whether it went live.
func (s *Server) saveModule(w http.ResponseWriter, r *http.Request, user store.User) {
	m, ok := s.module(w, r)
	if !ok {
		return
	}

	submitted := normalizeSubmission(r.FormValue("content"))

	if problems := configstore.ValidateJSON([]byte(submitted)); len(problems) != 0 {
		s.refuse(w, m, user, problems)
		return
	}

	before, err := s.Configs.Read(m)
	if err != nil {
		s.fail(w, err)
		return
	}

	// The editor carries the digest of what it was opened on. If the file has
	// moved since, somebody else saved in the meantime, and writing now would
	// drop their change without either of them being told — this codebase's
	// own failure mode, applied to the tool meant to prevent it.
	if base := r.FormValue("base"); base != before.SHA {
		s.refuse(w, m, user, []error{fmt.Errorf(
			"the file changed since you opened it — it is now %s. Reload the page to see it, then make your change again",
			describeVersion(before))})
		return
	}

	snap, err := s.Configs.Save(m, []byte(submitted))
	if err != nil {
		s.fail(w, err)
		return
	}

	if err := s.DB.Record(store.Entry{
		User:         user.Name,
		Module:       m.Name,
		Action:       store.ActionSave,
		SnapshotSHA:  snap.SHA,
		SnapshotName: snap.Name,
		PreviousSHA:  before.SHA,
	}); err != nil {
		s.fail(w, err)
		return
	}

	notice := "Saved " + snap.Short() + "."
	if before.Exists && before.SHA == snap.SHA {
		notice = "Saved — the file was already exactly this."
	}

	// Tell the page a save happened, so the panel beside the editor refreshes
	// now rather than at the end of its polling interval.
	w.Header().Set("HX-Trigger", "config-saved")
	s.renderPartial(w, "saveresult.html", page{Module: m, Notice: notice, BaseSHA: snap.SHA})
}

// refuse reports a save the controller would not write. Nothing reached the
// volume, so the service is untouched — but the attempt is recorded, because
// a refused save is the most interesting thing in the log when somebody asks
// why their change never appeared.
func (s *Server) refuse(w http.ResponseWriter, m module.Module, user store.User, problems []error) {
	reasons := make([]string, 0, len(problems))
	for _, problem := range problems {
		reasons = append(reasons, problem.Error())
	}

	if err := s.DB.Record(store.Entry{
		User:   user.Name,
		Module: m.Name,
		Action: store.ActionRejected,
		Note:   strings.Join(reasons, "; "),
	}); err != nil {
		s.fail(w, err)
		return
	}

	s.renderPartial(w, "saveresult.html", page{Module: m, Problems: reasons})
}

func describeVersion(c configstore.Content) string {
	if !c.Exists {
		return "gone"
	}
	return configstore.Short(c.SHA)
}

// restoreModule writes an old snapshot back as the live configuration.
//
// A restore is an ordinary save of old bytes: it goes through the same atomic
// write, produces the same audit entry with a different action, and reuses the
// snapshot it came from rather than making a copy. So a restore is itself
// undoable, and history stays append-only.
func (s *Server) restoreModule(w http.ResponseWriter, r *http.Request, user store.User) {
	m, ok := s.module(w, r)
	if !ok {
		return
	}

	sha := r.FormValue("sha")
	data, err := s.Configs.SnapshotData(m, sha)
	if err != nil {
		http.Error(w, "no such snapshot", http.StatusNotFound)
		return
	}

	before, err := s.Configs.Read(m)
	if err != nil {
		s.fail(w, err)
		return
	}

	snap, err := s.Configs.Save(m, data)
	if err != nil {
		s.fail(w, err)
		return
	}

	if err := s.DB.Record(store.Entry{
		User:         user.Name,
		Module:       m.Name,
		Action:       store.ActionRestore,
		SnapshotSHA:  snap.SHA,
		SnapshotName: snap.Name,
		PreviousSHA:  before.SHA,
		Note:         "restored the version from " + snap.Taken.Format("2006-01-02 15:04:05 UTC"),
	}); err != nil {
		s.fail(w, err)
		return
	}

	// A full reload rather than a fragment: the editor is now showing bytes
	// that are no longer on disk, and it has to be refilled.
	http.Redirect(w, r, "/modules/"+m.Name+"?notice=Restored+"+snap.Short(), http.StatusSeeOther)
}

func (s *Server) showSnapshot(w http.ResponseWriter, r *http.Request, user store.User) {
	m, ok := s.module(w, r)
	if !ok {
		return
	}

	sha := r.PathValue("sha")
	snap, err := s.Configs.Snapshot(m, sha)
	if err != nil {
		http.Error(w, "no such snapshot", http.StatusNotFound)
		return
	}
	data, err := s.Configs.SnapshotData(m, sha)
	if err != nil {
		http.Error(w, "no such snapshot", http.StatusNotFound)
		return
	}

	current, err := s.Configs.Read(m)
	if err != nil {
		s.fail(w, err)
		return
	}

	s.render(w, "snapshot.html", page{
		Title:        m.Title + " — " + snap.Short(),
		User:         user,
		CSRF:         s.csrfFor(r),
		Module:       m,
		Snapshot:     snap,
		SnapshotData: string(data),
		History:      []snapshotView{{Snapshot: snap, Current: snap.SHA == current.SHA}},
	})
}

func (s *Server) showAudit(w http.ResponseWriter, r *http.Request, user store.User) {
	entries, err := s.DB.Audit(r.URL.Query().Get("module"), 200)
	if err != nil {
		s.fail(w, err)
		return
	}

	s.render(w, "audit.html", page{
		Title: "Activity",
		User:  user,
		CSRF:  s.csrfFor(r),
		Audit: entries,
	})
}

// normalizeSubmission turns what a browser submits from a textarea into what
// belongs in a file: CRLF line endings become LF, and the file ends in a
// newline. Without this every save through the UI would differ from the same
// file written by hand, and the digests would never line up.
func normalizeSubmission(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content
}
