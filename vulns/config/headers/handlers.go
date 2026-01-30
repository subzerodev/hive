// vulns/config/headers/handlers.go
package headers

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// X-XSS-Protection disabled
		handlers.Handle("/vulns/config/headers/xss-filter-disabled", xssFilterDisabled)
		handlers.Handle("/vulns/config/headers/xss-filter-enabled", xssFilterEnabled)
		handlers.Handle("/vulns/config/headers/fp/xss-filter-block", fpXssFilterBlock)

		// X-Forwarded-For / Spoofable IP
		handlers.Handle("/vulns/config/headers/xff-bypass", xffBypass)
		handlers.Handle("/vulns/config/headers/client-ip-bypass", clientIPBypass)
		handlers.Handle("/vulns/config/headers/fp/xff-validated", fpXffValidated)

		// Multiple Content-Types
		handlers.Handle("/vulns/config/headers/multiple-content-types", multipleContentTypes)
		handlers.Handle("/vulns/config/headers/fp/single-content-type", fpSingleContentType)

		// Request URL Override
		handlers.Handle("/vulns/config/headers/url-override", urlOverride)
		handlers.Handle("/vulns/config/headers/url-override-legacy", urlOverrideLegacy)
		handlers.Handle("/vulns/config/headers/fp/url-override-ignored", fpUrlOverrideIgnored)
	})
}

// X-XSS-Protection tests
func xssFilterDisabled(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: X-XSS-Protection explicitly disabled
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("Content-Type", "text/html")

	input := r.URL.Query().Get("input")
	if input == "" {
		input = "<script>alert(1)</script>"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Filter Disabled</title></head>
<body>
<h1>Browser XSS Filter Disabled</h1>
<p>X-XSS-Protection: 0 header is set, disabling browser XSS filter.</p>

<h2>Test Input:</h2>
<form method="GET">
    <input name="input" value="%s" style="width:400px">
    <button type="submit">Submit</button>
</form>

<h2>Reflected Output:</h2>
<div>%s</div>

<h3>Vulnerability:</h3>
<p><small>Browser's built-in XSS filter is explicitly disabled</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, input, input)
}

func xssFilterEnabled(w http.ResponseWriter, r *http.Request) {
	// Partial protection: X-XSS-Protection: 1 (without mode=block)
	w.Header().Set("X-XSS-Protection", "1")
	w.Header().Set("Content-Type", "text/html")

	input := r.URL.Query().Get("input")
	if input == "" {
		input = "test"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Filter Enabled (No Block)</title></head>
<body>
<h1>XSS Filter Enabled Without Block Mode</h1>
<p>X-XSS-Protection: 1 (without mode=block)</p>
<p>Browser may sanitize but still render the page.</p>

<h2>Input:</h2>
<div>%s</div>

<h3>Note:</h3>
<p><small>Partial protection - should use mode=block</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, input)
}

func fpXssFilterBlock(w http.ResponseWriter, r *http.Request) {
	// SAFE: X-XSS-Protection: 1; mode=block
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Filter - Block Mode</title></head>
<body>
<h1>XSS Filter with Block Mode</h1>
<p>X-XSS-Protection: 1; mode=block</p>

<h3>Security:</h3>
<p><small>SAFE: Browser will block page on XSS detection</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`)
}

// X-Forwarded-For / Spoofable Client IP tests
func xffBypass(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trust X-Forwarded-For without validation
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// Simulate admin check based on IP
	isAdmin := clientIP == "127.0.0.1" || clientIP == "10.0.0.1" || clientIP == "192.168.1.1"

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>X-Forwarded-For Bypass</title></head>
<body>
<h1>X-Forwarded-For Security Bypass</h1>
<p>Server trusts X-Forwarded-For header for access control.</p>

<h2>Your Detected IP:</h2>
<pre>%s</pre>

<h2>Admin Access:</h2>
<pre>%v</pre>

<h3>Test:</h3>
<pre>curl -H "X-Forwarded-For: 127.0.0.1" URL</pre>

<h3>Vulnerability:</h3>
<p><small>Trusting client-provided X-Forwarded-For for authorization</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, clientIP, isAdmin)
}

func clientIPBypass(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Trust multiple IP headers
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Forwarded-For")
	}
	if clientIP == "" {
		clientIP = r.Header.Get("X-Client-IP")
	}
	if clientIP == "" {
		clientIP = r.Header.Get("X-Originating-IP")
	}
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// Simulate rate limiting based on IP
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Client IP Spoofing</title></head>
<body>
<h1>Spoofable Client IP Address</h1>
<p>Server checks multiple headers for client IP.</p>

<h2>Detected IP:</h2>
<pre>%s</pre>

<h2>Headers Checked:</h2>
<ul>
    <li>X-Real-IP: %s</li>
    <li>X-Forwarded-For: %s</li>
    <li>X-Client-IP: %s</li>
    <li>X-Originating-IP: %s</li>
</ul>

<h3>Test:</h3>
<pre>curl -H "X-Real-IP: 1.2.3.4" URL</pre>

<h3>Vulnerability:</h3>
<p><small>IP-based controls can be bypassed via spoofed headers</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, clientIP,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Client-IP"),
		r.Header.Get("X-Originating-IP"))
}

func fpXffValidated(w http.ResponseWriter, r *http.Request) {
	// SAFE: Only trust RemoteAddr, ignore forwarded headers
	clientIP := r.RemoteAddr

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>X-Forwarded-For Validated</title></head>
<body>
<h1>Proper Client IP Handling</h1>
<p>Server only trusts actual connection IP, not forwarded headers.</p>

<h2>Connection IP:</h2>
<pre>%s</pre>

<h2>Ignored Headers:</h2>
<pre>
X-Forwarded-For: %s (ignored)
X-Real-IP: %s (ignored)
</pre>

<h3>Security:</h3>
<p><small>SAFE: Only trusts verified connection source</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, clientIP, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
}

// Multiple Content-Types tests
func multipleContentTypes(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Multiple Content-Type headers
	w.Header().Add("Content-Type", "text/html")
	w.Header().Add("Content-Type", "text/plain")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Multiple Content-Types</title></head>
<body>
<h1>Multiple Content-Type Headers</h1>
<p>Response has multiple Content-Type headers set.</p>

<h2>Headers:</h2>
<pre>
Content-Type: text/html
Content-Type: text/plain
</pre>

<h3>Vulnerability:</h3>
<p><small>Ambiguous content type - browser behavior undefined</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`)
}

func fpSingleContentType(w http.ResponseWriter, r *http.Request) {
	// SAFE: Single Content-Type header
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Single Content-Type</title></head>
<body>
<h1>Single Content-Type Header</h1>
<p>Response has exactly one Content-Type header.</p>

<h2>Header:</h2>
<pre>Content-Type: text/html; charset=utf-8</pre>

<h3>Security:</h3>
<p><small>SAFE: Unambiguous content type</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`)
}

// Request URL Override tests (X-Original-URL, X-Rewrite-URL, X-Forwarded-Path)
func urlOverride(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Process X-Original-URL and X-Rewrite-URL headers
	originalURL := r.Header.Get("X-Original-URL")
	rewriteURL := r.Header.Get("X-Rewrite-URL")
	forwardedPath := r.Header.Get("X-Forwarded-Path")

	effectiveURL := r.URL.Path
	if originalURL != "" {
		effectiveURL = originalURL
	} else if rewriteURL != "" {
		effectiveURL = rewriteURL
	} else if forwardedPath != "" {
		effectiveURL = forwardedPath
	}

	// Simulate access control based on effective URL
	isAdmin := effectiveURL == "/admin" || effectiveURL == "/admin/"
	isRestricted := effectiveURL == "/restricted" || effectiveURL == "/internal"

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Request URL Override</title></head>
<body>
<h1>Request URL Override Vulnerability</h1>
<p>Server processes URL override headers for routing.</p>

<h2>Request Analysis:</h2>
<table border="1" cellpadding="5">
    <tr><td>Actual URL</td><td>%s</td></tr>
    <tr><td>X-Original-URL</td><td>%s</td></tr>
    <tr><td>X-Rewrite-URL</td><td>%s</td></tr>
    <tr><td>X-Forwarded-Path</td><td>%s</td></tr>
    <tr><td><strong>Effective URL</strong></td><td><strong>%s</strong></td></tr>
</table>

<h2>Access Control Result:</h2>
<pre>
Admin Access: %v
Restricted Access: %v
</pre>

<h3>Test:</h3>
<pre>
curl -H "X-Original-URL: /admin" URL
curl -H "X-Rewrite-URL: /restricted" URL
</pre>

<h3>Vulnerability:</h3>
<p><small>URL override headers can bypass access controls</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, r.URL.Path, originalURL, rewriteURL, forwardedPath, effectiveURL, isAdmin, isRestricted)
}

func urlOverrideLegacy(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Legacy URL override headers
	redirect := r.Header.Get("Redirect")
	xHost := r.Header.Get("X-Host")
	xForwardedServer := r.Header.Get("X-Forwarded-Server")
	xHTTPDestinationURL := r.Header.Get("X-HTTP-DestinationURL")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Legacy URL Override Headers</title></head>
<body>
<h1>Legacy Request URL Override</h1>
<p>Server processes legacy URL/host override headers.</p>

<h2>Headers Detected:</h2>
<table border="1" cellpadding="5">
    <tr><td>Redirect</td><td>%s</td></tr>
    <tr><td>X-Host</td><td>%s</td></tr>
    <tr><td>X-Forwarded-Server</td><td>%s</td></tr>
    <tr><td>X-HTTP-DestinationURL</td><td>%s</td></tr>
</table>

<h3>Test:</h3>
<pre>
curl -H "Redirect: /admin" URL
curl -H "X-Host: admin.internal" URL
curl -H "X-HTTP-DestinationURL: http://admin/" URL
</pre>

<h3>Vulnerability:</h3>
<p><small>Legacy headers can manipulate request routing</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, redirect, xHost, xForwardedServer, xHTTPDestinationURL)
}

func fpUrlOverrideIgnored(w http.ResponseWriter, r *http.Request) {
	// SAFE: Ignore all URL override headers
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>URL Override Headers Ignored</title></head>
<body>
<h1>URL Override Headers Ignored</h1>
<p>Server ignores all URL override headers and uses actual request URL.</p>

<h2>Request Analysis:</h2>
<table border="1" cellpadding="5">
    <tr><td>Actual URL</td><td>%s</td></tr>
    <tr><td>X-Original-URL</td><td>%s (ignored)</td></tr>
    <tr><td>X-Rewrite-URL</td><td>%s (ignored)</td></tr>
</table>

<h3>Security:</h3>
<p><small>SAFE: URL override headers are not processed</small></p>
<p><a href="/vulns/config/headers/">Back</a></p>
</body></html>`, r.URL.Path, r.Header.Get("X-Original-URL"), r.Header.Get("X-Rewrite-URL"))
}
