package csp

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/csp/missing", missing)
		handlers.Handle("/vulns/config/csp/unsafe-inline", unsafeInline)
		handlers.Handle("/vulns/config/csp/fp/strict", fpStrict)
	})
}

func missing(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No CSP header
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSP - Missing</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>No Content Security Policy</h1>
<p>This page has no CSP header. Inline scripts execute freely.</p>
<script>document.write('<p>Inline script executed!</p>');</script>
<p><small>VULNERABLE: No CSP protection</small></p>
</div>
</body></html>`)
}

func unsafeInline(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: CSP allows unsafe-inline
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSP - Unsafe Inline</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Weak CSP with unsafe-inline</h1>
<p>CSP: default-src 'self' 'unsafe-inline' 'unsafe-eval'</p>
<script>document.write('<p>Inline script still works!</p>');</script>
<p><small>VULNERABLE: CSP allows unsafe-inline and unsafe-eval</small></p>
</div>
</body></html>`)
}

func fpStrict(w http.ResponseWriter, r *http.Request) {
	// SAFE: Strict CSP
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSP - Strict</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Strict Content Security Policy</h1>
<p>CSP: default-src 'self'; script-src 'self'; ...</p>
<p>Inline scripts are blocked by this policy.</p>
<p><small>SAFE: Strict CSP without unsafe-inline</small></p>
</div>
</body></html>`)
}
