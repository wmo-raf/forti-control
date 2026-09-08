package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/metno/forti-control/internal/store"
)

const sessionCookie = "forti_control_session"

type contextKey string

const userKey contextKey = "user"

// requireUser wraps a handler so that only a signed-in user reaches it, and
// checks the CSRF token on anything that changes something.
//
// The redirect for a signed-out user goes to the login page for an ordinary
// request, but an htmx request is a fragment of an already-loaded page: it is
// answered with a header that makes the browser navigate, so that a session
// expiring behind a polling status panel does not paste a login form into the
// middle of the editor.
func (s *Server) requireUser(next func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			s.redirectToLogin(w, r)
			return
		}

		user, err := s.DB.SessionUser(cookie.Value)
		if errors.Is(err, store.ErrNoSession) {
			s.clearSessionCookie(w)
			s.redirectToLogin(w, r)
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !hmac.Equal([]byte(r.FormValue("csrf")), []byte(s.csrfToken(cookie.Value))) {
				http.Error(w, "this form has expired; reload the page and try again", http.StatusForbidden)
				return
			}
		}

		next(w, r, user)
	}
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// csrfToken derives a per-session token from the session token and a key kept
// in the database. Nothing has to be stored per form, and a token from one
// session is useless in another.
func (s *Server) csrfToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	mac.Write([]byte(sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// csrfFor returns the token to put in the forms on this request's page.
func (s *Server) csrfFor(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return s.csrfToken(cookie.Value)
}

func (s *Server) showLogin(w http.ResponseWriter, r *http.Request) {
	// Somebody with a working session has no business on the login page.
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if _, err := s.DB.SessionUser(cookie.Value); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	s.render(w, "login.html", page{Title: "Sign in", CSRF: s.loginToken(w, r)})
}

func (s *Server) doLogin(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("username")
	password := r.FormValue("password")

	if !checkLoginToken(r) {
		s.renderStatus(w, http.StatusForbidden, "login.html", page{
			Title: "Sign in",
			CSRF:  s.loginToken(w, r),
			Error: "That sign-in form was stale. Try again.",
		})
		return
	}

	// Guessing has to be slow. Without this the only thing between an
	// attacker and a service that edits production configuration is how fast
	// bcrypt runs.
	if s.throttle.blocked(name, time.Now()) {
		s.renderStatus(w, http.StatusTooManyRequests, "login.html", page{
			Title:    "Sign in",
			CSRF:     s.loginToken(w, r),
			Username: name,
			Error:    "Too many failed attempts. Wait a few minutes and try again.",
		})
		return
	}

	user, err := s.DB.Authenticate(name, password)
	if errors.Is(err, store.ErrNoSuchUser) {
		s.throttle.fail(name, time.Now())
		s.renderStatus(w, http.StatusUnauthorized, "login.html", page{
			Title:    "Sign in",
			CSRF:     s.loginToken(w, r),
			Username: name,
			Error:    "That username and password do not match.",
		})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.throttle.succeed(name)

	token, err := s.DB.NewSession(user.ID, SessionLifetime)
	if err != nil {
		s.fail(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(SessionLifetime),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) doLogout(w http.ResponseWriter, r *http.Request, _ store.User) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if err := s.DB.DeleteSession(cookie.Value); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
