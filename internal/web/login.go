package web

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const loginCookie = "forti_control_login"

// loginAttempts is how many failures an account tolerates inside
// loginWindow before it stops answering. It is generous enough that nobody
// mistyping their password notices, and small enough that guessing at any
// useful rate does not work.
const (
	loginAttempts = 10
	loginWindow   = 15 * time.Minute
)

// A throttle counts recent failed logins per account.
//
// It is in memory, so restarting the controller clears it — which is fine:
// the controller is not the thing an attacker can restart, and the point is
// to make online guessing slow rather than to keep a permanent record.
type throttle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newThrottle() *throttle {
	return &throttle{failures: map[string][]time.Time{}}
}

// blocked reports whether this name has failed too often recently.
func (t *throttle) blocked(name string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recent(name, now)) >= loginAttempts
}

// fail records a failed attempt.
func (t *throttle) fail(name string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures[name] = append(t.recent(name, now), now)
}

// succeed forgets a name's failures, so that somebody who eventually
// remembers their password is not locked out by the attempts before it.
func (t *throttle) succeed(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, name)
}

// recent drops attempts that have aged out and returns the rest. The caller
// holds the lock.
func (t *throttle) recent(name string, now time.Time) []time.Time {
	kept := t.failures[name][:0]
	for _, at := range t.failures[name] {
		if now.Sub(at) < loginWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(t.failures, name)
		return nil
	}
	t.failures[name] = kept
	return kept
}

// loginToken issues, or reuses, the token that ties a login form to the
// browser that asked for it.
//
// The session-derived token used everywhere else is not available here: there
// is no session yet. So the form carries a random value that is also set as a
// cookie, and the two must match — the standard double-submit. Another site
// can make a browser post to this endpoint, but it cannot read the cookie to
// put the matching value in its form, so it cannot sign somebody into an
// account of its choosing.
func (s *Server) loginToken(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(loginCookie); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	token := hex.EncodeToString(raw)

	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * time.Minute).Seconds()),
	})
	return token
}

// checkLoginToken reports whether the submitted form came from a login page
// this browser was given.
func checkLoginToken(r *http.Request) bool {
	cookie, err := r.Cookie(loginCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	return hmac.Equal([]byte(cookie.Value), []byte(r.FormValue("csrf")))
}

// secureHeaders sets the headers that limit what a browser will do with these
// pages. Everything the UI needs is served from the controller itself — htmx
// and the stylesheet are embedded in the binary — so the policy can refuse
// every other origin outright.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
