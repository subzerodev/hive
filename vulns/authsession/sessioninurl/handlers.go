package sessioninurl

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth-session/session-in-url/exposed", exposed)
		handlers.Handle("/vulns/auth-session/session-in-url/fp/header-based", fpHeaderBased)
	})
}

func exposed(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionid")
	if sessionID == "" {
		sessionID = "abc123xyz789"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Session ID in URL - exposed in logs, referer, history
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Session in URL - Exposed</title></head>
<body>
<h1>Dashboard (Session in URL)</h1>
<p>Your session: %s</p>
<p>Navigation:</p>
<ul>
    <li><a href="/vulns/auth-session/session-in-url/exposed?sessionid=%s">Profile</a></li>
    <li><a href="/vulns/auth-session/session-in-url/exposed?sessionid=%s">Settings</a></li>
</ul>
<p><small>VULNERABLE: Session ID exposed in URL</small></p>
</body></html>`, sessionID, sessionID, sessionID)
}

func fpHeaderBased(w http.ResponseWriter, r *http.Request) {
	// SAFE: Session in cookie (header-based)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "secure_session_abc123",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Session - Header Based</title></head>
<body>
<h1>Dashboard (Secure Session)</h1>
<p>Session stored securely in cookie header.</p>
<p>Navigation:</p>
<ul>
    <li><a href="/vulns/auth-session/session-in-url/fp/header-based">Profile</a></li>
    <li><a href="/vulns/auth-session/session-in-url/fp/header-based">Settings</a></li>
</ul>
<p><small>SAFE: Session ID in secure cookie, not URL</small></p>
</body></html>`)
}
