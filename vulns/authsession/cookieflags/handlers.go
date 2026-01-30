package cookieflags

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth-session/cookie-flags/missing-httponly", missingHttpOnly)
		handlers.Handle("/vulns/auth-session/cookie-flags/missing-secure", missingSecure)
		handlers.Handle("/vulns/auth-session/cookie-flags/missing-samesite", missingSameSite)
		handlers.Handle("/vulns/auth-session/cookie-flags/fp/all-flags", fpAllFlags)
	})
}

func missingHttpOnly(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Cookie without HttpOnly flag - accessible via JavaScript
	http.SetCookie(w, &http.Cookie{
		Name:  "session_no_httponly",
		Value: "abc123",
		Path:  "/",
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cookie - Missing HttpOnly</title></head>
<body>
<h1>Cookie Set (Missing HttpOnly)</h1>
<p>Cookie "session_no_httponly" has been set without HttpOnly flag.</p>
<p>JavaScript can access this cookie:</p>
<pre id="cookie"></pre>
<script>document.getElementById('cookie').textContent = document.cookie;</script>
<p><small>VULNERABLE: Cookie accessible via document.cookie</small></p>
</body></html>`)
}

func missingSecure(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Cookie without Secure flag - sent over HTTP
	http.SetCookie(w, &http.Cookie{
		Name:     "session_no_secure",
		Value:    "abc123",
		Path:     "/",
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cookie - Missing Secure</title></head>
<body>
<h1>Cookie Set (Missing Secure)</h1>
<p>Cookie "session_no_secure" has been set without Secure flag.</p>
<p><small>VULNERABLE: Cookie can be transmitted over HTTP</small></p>
</body></html>`)
}

func missingSameSite(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Cookie without SameSite - vulnerable to CSRF
	http.SetCookie(w, &http.Cookie{
		Name:     "session_no_samesite",
		Value:    "abc123",
		Path:     "/",
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cookie - Missing SameSite</title></head>
<body>
<h1>Cookie Set (Missing SameSite)</h1>
<p>Cookie "session_no_samesite" has been set without SameSite flag.</p>
<p><small>VULNERABLE: Cookie sent on cross-site requests</small></p>
</body></html>`)
}

func fpAllFlags(w http.ResponseWriter, r *http.Request) {
	// SAFE: Cookie with all security flags
	http.SetCookie(w, &http.Cookie{
		Name:     "session_secure",
		Value:    "abc123",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cookie - All Flags</title></head>
<body>
<h1>Cookie Set (All Flags)</h1>
<p>Cookie "session_secure" has been set with all security flags:</p>
<ul>
    <li>HttpOnly: true</li>
    <li>Secure: true</li>
    <li>SameSite: Strict</li>
</ul>
<p><small>SAFE: All cookie security flags enabled</small></p>
</body></html>`)
}
