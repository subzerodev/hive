package authbypass

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth-session/auth-bypass/403-bypass", bypass403)
		handlers.Handle("/vulns/auth-session/auth-bypass/header-abuse", headerAbuse)
		handlers.Handle("/vulns/auth-session/auth-bypass/fp/proper-check", fpProperCheck)
	})
}

func bypass403(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/admin"
	}

	// VULNERABLE: 403 bypass via path manipulation
	// In real apps, this would check different path variations
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>403 Bypass Test</title></head>
<body>
<h1>403 Bypass Testing</h1>
<form method="GET">
    <input name="path" value="%s" placeholder="Path to test">
    <button type="submit">Test</button>
</form>
<h2>Bypass Techniques:</h2>
<ul>
    <li><a href="?path=/admin">Original: /admin (403)</a></li>
    <li><a href="?path=/admin/">Trailing slash: /admin/</a></li>
    <li><a href="?path=/admin/..">Path traversal: /admin/..</a></li>
    <li><a href="?path=/ADMIN">Case variation: /ADMIN</a></li>
    <li><a href="?path=/admin%%2f">URL encoding: /admin%%2f</a></li>
</ul>
<p>Requested: %s</p>
<p><small>VULNERABLE: No consistent path normalization</small></p>
</body></html>`, path, path)
}

func headerAbuse(w http.ResponseWriter, r *http.Request) {
	// Check for header-based auth bypass attempts
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	xOriginalUrl := r.Header.Get("X-Original-URL")
	xRewriteUrl := r.Header.Get("X-Rewrite-URL")

	// VULNERABLE: Trusts headers without validation
	accessGranted := false
	if xForwardedFor == "127.0.0.1" || xForwardedFor == "localhost" {
		accessGranted = true
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Header-Based Auth</title></head>
<body>
<h1>Admin Panel (Header-Based Auth)</h1>
<p>X-Forwarded-For: %s</p>
<p>X-Original-URL: %s</p>
<p>X-Rewrite-URL: %s</p>
<p><strong>Access: %s</strong></p>
<h2>Bypass Techniques:</h2>
<pre>
curl -H "X-Forwarded-For: 127.0.0.1" [url]
curl -H "X-Original-URL: /admin" [url]
curl -H "X-Rewrite-URL: /admin" [url]
</pre>
<p><small>VULNERABLE: Trusts X-Forwarded-For header</small></p>
</body></html>`, xForwardedFor, xOriginalUrl, xRewriteUrl, map[bool]string{true: "GRANTED", false: "DENIED"}[accessGranted])
}

func fpProperCheck(w http.ResponseWriter, r *http.Request) {
	// SAFE: Proper authentication check
	authHeader := r.Header.Get("Authorization")

	w.Header().Set("Content-Type", "text/html")

	// Check for valid auth (in real app, this would verify token)
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
<h1>Access Denied</h1>
<p>Valid authentication required.</p>
<p><small>SAFE: Proper authentication check, headers ignored</small></p>
</body></html>`)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel (Authenticated)</h1>
<p>Welcome, authenticated user!</p>
<p><small>SAFE: Access granted via valid token only</small></p>
</body></html>`)
}
