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

		// Cookie loosely scoped
		handlers.Handle("/vulns/auth-session/cookie-flags/loosely-scoped", looselyScoped)
		handlers.Handle("/vulns/auth-session/cookie-flags/fp/properly-scoped", fpProperlyScoped)
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
<head><title>Cookie - Missing HttpOnly</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cookie Set (Missing HttpOnly)</h1>
<p>Cookie "session_no_httponly" has been set without HttpOnly flag.</p>
<p>JavaScript can access this cookie:</p>
<pre id="cookie"></pre>
<script>document.getElementById('cookie').textContent = document.cookie;</script>
<p><small>VULNERABLE: Cookie accessible via document.cookie</small></p>
</div>
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
<head><title>Cookie - Missing Secure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cookie Set (Missing Secure)</h1>
<p>Cookie "session_no_secure" has been set without Secure flag.</p>
<p><small>VULNERABLE: Cookie can be transmitted over HTTP</small></p>
</div>
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
<head><title>Cookie - Missing SameSite</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cookie Set (Missing SameSite)</h1>
<p>Cookie "session_no_samesite" has been set without SameSite flag.</p>
<p><small>VULNERABLE: Cookie sent on cross-site requests</small></p>
</div>
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
<head><title>Cookie - All Flags</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cookie Set (All Flags)</h1>
<p>Cookie "session_secure" has been set with all security flags:</p>
<ul>
    <li>HttpOnly: true</li>
    <li>Secure: true</li>
    <li>SameSite: Strict</li>
</ul>
<p><small>SAFE: All cookie security flags enabled</small></p>
</div>
</body></html>`)
}

func looselyScoped(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Cookie scoped to parent domain
	http.SetCookie(w, &http.Cookie{
		Name:   "session_loose",
		Value:  "abc123",
		Domain: ".example.com", // Scoped to parent domain
		Path:   "/",
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cookie - Loosely Scoped</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cookie Loosely Scoped to Parent Domain</h1>
<p>Cookie "session_loose" is scoped to parent domain.</p>

<h2>Cookie Set:</h2>
<pre>Set-Cookie: session_loose=abc123; Domain=.example.com; Path=/</pre>

<h2>Issue:</h2>
<p>This cookie will be sent to ALL subdomains of example.com:</p>
<ul>
    <li>app.example.com</li>
    <li>api.example.com</li>
    <li>untrusted.example.com</li>
</ul>

<h3>Vulnerability:</h3>
<p><small>Cookie can be accessed by other subdomains, risking session hijacking</small></p>
<p><a href="/vulns/auth-session/cookie-flags/">Back</a></p>
</div>
</body></html>`)
}

func fpProperlyScoped(w http.ResponseWriter, r *http.Request) {
	// SAFE: Cookie properly scoped to specific subdomain
	http.SetCookie(w, &http.Cookie{
		Name:     "session_scoped",
		Value:    "abc123",
		Domain:   "app.example.com", // Specific subdomain only
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cookie - Properly Scoped</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cookie Properly Scoped</h1>
<p>Cookie "session_scoped" is scoped to specific subdomain only.</p>

<h2>Cookie Set:</h2>
<pre>Set-Cookie: session_scoped=abc123; Domain=app.example.com; Path=/; HttpOnly; Secure</pre>

<h3>Security:</h3>
<p><small>SAFE: Cookie only sent to specific subdomain</small></p>
<p><a href="/vulns/auth-session/cookie-flags/">Back</a></p>
</div>
</body></html>`)
}
