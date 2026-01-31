// vulns/redirect/handlers.go
package redirect

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Basic open redirect via Location header
		handlers.Handle("/vulns/redirect/basic", basic)
		// Meta refresh redirect
		handlers.Handle("/vulns/redirect/meta", meta)
		// JavaScript redirect
		handlers.Handle("/vulns/redirect/javascript", javascript)
		// URL parameter append
		handlers.Handle("/vulns/redirect/parameter", parameter)
		// Double encoding bypass
		handlers.Handle("/vulns/redirect/double-encode", doubleEncode)
		// False positive - validated whitelist
		handlers.Handle("/vulns/redirect/fp/whitelist", fpWhitelist)
		// False positive - same domain check
		handlers.Handle("/vulns/redirect/fp/domain", fpDomain)
	})
}

func basic(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/vulns/"
	}

	// Show form if no redirect target or viewing page
	if r.URL.Query().Get("redirect") == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Basic</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Open Redirect - Basic</h1>
<form method="GET">
    <input name="url" value="%s" placeholder="Redirect URL" style="width:300px">
    <input type="hidden" name="redirect" value="1">
    <button type="submit">Redirect</button>
</form>
<h3>Hint:</h3>
<p><small>Try: //evil.com or https://evil.com</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, target)
		return
	}

	// VULNERABLE: Open redirect via Location header
	http.Redirect(w, r, target, http.StatusFound)
}

func meta(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/vulns/"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Open redirect via meta refresh
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Open Redirect - Meta Refresh</title>
    <link rel="stylesheet" href="/static/css/hive.css">
    <meta http-equiv="refresh" content="0;url=%s">
</head>
<body>
<div class="container">
<h1>Open Redirect - Meta Refresh</h1>
<p>Redirecting to: %s</p>
<p>If not redirected, <a href="%s">click here</a></p>
<h3>Hint:</h3>
<p><small>Try: ?url=https://evil.com</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, target, target, target)
}

func javascript(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/vulns/"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Open redirect via JavaScript
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Open Redirect - JavaScript</title>
    <link rel="stylesheet" href="/static/css/hive.css">
    <script>
        window.location = "%s";
    </script>
</head>
<body>
<div class="container">
<h1>Open Redirect - JavaScript</h1>
<p>Redirecting to: %s</p>
<h3>Hint:</h3>
<p><small>Try: ?url=https://evil.com</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, target, target)
}

func parameter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("next")
	if path == "" {
		path = "/dashboard"
	}

	// Simulate login page with redirect
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Parameter</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (Redirect After)</h1>
<form method="GET">
    <input type="text" placeholder="Username"><br><br>
    <input type="password" placeholder="Password"><br><br>
    <input name="next" value="%s" placeholder="Redirect after login" style="width:300px"><br><br>
    <input type="hidden" name="login" value="1">
    <button type="submit">Login</button>
</form>
<h3>Hint:</h3>
<p><small>Try: ?next=https://evil.com/phishing</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, path)

	// If login submitted, redirect
	if r.URL.Query().Get("login") != "" {
		// VULNERABLE: Redirect to user-controlled URL
		http.Redirect(w, r, path, http.StatusFound)
	}
}

func doubleEncode(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/vulns/"
	}

	// Single decode (simulates common bypass)
	decoded, _ := url.QueryUnescape(target)

	if r.URL.Query().Get("redirect") == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Double Encode</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Open Redirect - Double Encode Bypass</h1>
<p>This endpoint decodes the URL once, allowing double-encoded bypasses.</p>
<form method="GET">
    <input name="url" value="%s" placeholder="Redirect URL" style="width:300px">
    <input type="hidden" name="redirect" value="1">
    <button type="submit">Redirect</button>
</form>
<h3>Hint:</h3>
<p><small>Try double-encoding: %%2568ttps://evil.com (%%25 = %%, then %%68 = h)</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, target)
		return
	}

	// VULNERABLE: Only single-decode, double-encoded bypasses work
	http.Redirect(w, r, decoded, http.StatusFound)
}

func fpWhitelist(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/vulns/"
	}

	// SAFE: Whitelist of allowed redirect paths
	allowed := map[string]bool{
		"/vulns/":     true,
		"/dashboard":  true,
		"/profile":    true,
		"/settings":   true,
	}

	if !allowed[target] {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Open Redirect - Safe (Whitelist)</h1>
<h2>Error:</h2>
<p>Redirect target not in allowed list.</p>
<p>Allowed: /vulns/, /dashboard, /profile, /settings</p>
<p><a href="/vulns/redirect/fp/whitelist">Try again</a></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`)
		return
	}

	if r.URL.Query().Get("redirect") != "" {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Open Redirect - Safe (Whitelist)</h1>
<form method="GET">
    <input name="url" value="%s" placeholder="Redirect URL" style="width:300px">
    <input type="hidden" name="redirect" value="1">
    <button type="submit">Redirect</button>
</form>
<h3>Filter:</h3>
<p><small>SAFE: Only whitelisted paths allowed (/vulns/, /dashboard, /profile, /settings)</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, target)
}

func fpDomain(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/vulns/"
	}

	// SAFE: Validate same domain
	parsedURL, err := url.Parse(target)
	if err != nil || (parsedURL.Host != "" && !strings.HasSuffix(parsedURL.Host, "localhost:8080")) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Open Redirect - Safe (Domain Check)</h1>
<h2>Error:</h2>
<p>External domains not allowed. Only localhost:8080 permitted.</p>
<p><a href="/vulns/redirect/fp/domain">Try again</a></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`)
		return
	}

	if r.URL.Query().Get("redirect") != "" {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Open Redirect - Safe (Domain Check)</h1>
<form method="GET">
    <input name="url" value="%s" placeholder="Redirect URL" style="width:300px">
    <input type="hidden" name="redirect" value="1">
    <button type="submit">Redirect</button>
</form>
<h3>Filter:</h3>
<p><small>SAFE: Only same-domain or relative paths allowed</small></p>
<p><a href="/vulns/redirect/">Back to Redirect Tests</a></p>
</div>
</body></html>`, target)
}
