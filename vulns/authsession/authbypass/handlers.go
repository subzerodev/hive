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

		// Additional header-based auth bypass tests (EVWA parity)
		handlers.Handle("/vulns/auth-session/auth-bypass/x-real-ip", xRealIP)
		handlers.Handle("/vulns/auth-session/auth-bypass/x-client-ip", xClientIP)
		handlers.Handle("/vulns/auth-session/auth-bypass/x-true-ip", xTrueIP)
		handlers.Handle("/vulns/auth-session/auth-bypass/x-forwarded-by", xForwardedBy)
		handlers.Handle("/vulns/auth-session/auth-bypass/x-custom-ip", xCustomIP)
		handlers.Handle("/vulns/auth-session/auth-bypass/client-ip", clientIP)
		handlers.Handle("/vulns/auth-session/auth-bypass/forwarded", forwarded)
		handlers.Handle("/vulns/auth-session/auth-bypass/referer", refererBypass)
		handlers.Handle("/vulns/auth-session/auth-bypass/fp/validated-headers", fpValidatedHeaders)
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

// expectedIPs contains IP addresses that grant admin access when spoofed
var expectedIPs = []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:127.0.0.1", "0:0:0:0:0:0:0:1", "localhost"}

func checkIPBypass(ip string) bool {
	for _, expected := range expectedIPs {
		if ip == expected {
			return true
		}
	}
	return false
}

func renderBypassResult(w http.ResponseWriter, headerName, headerValue string, granted bool) {
	status := "DENIED"
	if granted {
		status = "GRANTED"
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Auth Bypass - %s</title></head>
<body>
<h1>Admin Access Check</h1>
<p>Header: <code>%s</code></p>
<p>Value: <code>%s</code></p>
<p><strong>Access: %s</strong></p>
<h2>Test:</h2>
<pre>curl -H "%s: 127.0.0.1" [url]</pre>
<p><small>VULNERABLE: Trusts %s header for authentication</small></p>
</body></html>`, headerName, headerName, headerValue, status, headerName, headerName)
}

func xRealIP(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts X-Real-IP header
	ip := r.Header.Get("X-Real-IP")
	granted := checkIPBypass(ip)
	renderBypassResult(w, "X-Real-IP", ip, granted)
}

func xClientIP(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts X-Client-IP header
	ip := r.Header.Get("X-Client-IP")
	granted := checkIPBypass(ip)
	renderBypassResult(w, "X-Client-IP", ip, granted)
}

func xTrueIP(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts X-True-IP header
	ip := r.Header.Get("X-True-IP")
	granted := checkIPBypass(ip)
	renderBypassResult(w, "X-True-IP", ip, granted)
}

func xForwardedBy(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts X-Forwarded-By header
	ip := r.Header.Get("X-Forwarded-By")
	granted := checkIPBypass(ip)
	renderBypassResult(w, "X-Forwarded-By", ip, granted)
}

func xCustomIP(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts X-Custom-IP-Authorization header
	ip := r.Header.Get("X-Custom-IP-Authorization")
	granted := checkIPBypass(ip)
	renderBypassResult(w, "X-Custom-IP-Authorization", ip, granted)
}

func clientIP(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts Client-IP header
	ip := r.Header.Get("Client-IP")
	granted := checkIPBypass(ip)
	renderBypassResult(w, "Client-IP", ip, granted)
}

func forwarded(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts Forwarded header (RFC 7239)
	raw := r.Header.Get("Forwarded")
	var forIP string

	if raw != "" {
		// Parse Forwarded header: for=192.0.2.60;proto=http;by=203.0.113.43
		parts := strings.Split(raw, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "for=") {
				forIP = strings.Trim(part[4:], "\" []")
				break
			}
		}
	}

	granted := checkIPBypass(forIP)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Auth Bypass - Forwarded</title></head>
<body>
<h1>Admin Access Check</h1>
<p>Header: <code>Forwarded</code></p>
<p>Raw: <code>%s</code></p>
<p>Parsed for=: <code>%s</code></p>
<p><strong>Access: %s</strong></p>
<h2>Test:</h2>
<pre>curl -H "Forwarded: for=127.0.0.1" [url]</pre>
<p><small>VULNERABLE: Trusts Forwarded header for authentication</small></p>
</body></html>`, raw, forIP, map[bool]string{true: "GRANTED", false: "DENIED"}[granted])
}

func refererBypass(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trusts Referer header for access control
	referer := r.Header.Get("Referer")
	granted := referer == "http://localhost/" || referer == "http://127.0.0.1/" ||
		strings.HasPrefix(referer, "http://localhost:") || strings.HasPrefix(referer, "http://127.0.0.1:")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Auth Bypass - Referer</title></head>
<body>
<h1>Admin Access Check</h1>
<p>Header: <code>Referer</code></p>
<p>Value: <code>%s</code></p>
<p><strong>Access: %s</strong></p>
<h2>Test:</h2>
<pre>curl -H "Referer: http://localhost/" [url]</pre>
<p><small>VULNERABLE: Trusts Referer header for authentication</small></p>
</body></html>`, referer, map[bool]string{true: "GRANTED", false: "DENIED"}[granted])
}

func fpValidatedHeaders(w http.ResponseWriter, r *http.Request) {
	// SAFE: Does not trust any spoofable headers
	// Only uses actual remote address from connection
	remoteAddr := r.RemoteAddr

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Auth Check - Validated</title></head>
<body>
<h1>Admin Access Check (Secure)</h1>
<p>Remote Address: <code>%s</code></p>
<p>X-Forwarded-For: <code>%s</code> (ignored)</p>
<p>X-Real-IP: <code>%s</code> (ignored)</p>
<p><strong>Access: Based on actual connection only</strong></p>
<p><small>SAFE: Does not trust client-provided headers</small></p>
</body></html>`, remoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
}
