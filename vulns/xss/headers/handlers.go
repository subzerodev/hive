package headers

import (
	"fmt"
	"html"
	"net/http"
	"time"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Header-based XSS
		handlers.Handle("/vulns/xss/headers/referer", refererXSS)
		handlers.Handle("/vulns/xss/headers/user-agent", userAgentXSS)
		handlers.Handle("/vulns/xss/headers/cookie", cookieXSS)
		handlers.Handle("/vulns/xss/headers/cookie/set", cookieSet)
		handlers.Handle("/vulns/xss/headers/x-forwarded-for", xForwardedForXSS)
		handlers.Handle("/vulns/xss/headers/accept-language", acceptLanguageXSS)

		// FP - Headers properly escaped
		handlers.Handle("/vulns/xss/headers/fp/escaped", fpEscaped)
	})
}

// Referer header XSS
func refererXSS(w http.ResponseWriter, r *http.Request) {
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "(no referer)"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Referer header reflected without escaping
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Headers - Referer</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XSS in Referer Header</h1>
<h2>You came from:</h2>
<div>%s</div>
<p><small>VULNERABLE: Referer header reflected without escaping</small></p>
<p><small>Test with: curl -H "Referer: &lt;script&gt;alert(1)&lt;/script&gt;" URL</small></p>
<p><a href="/vulns/xss/headers/">Back to Header Tests</a></p>
</div>
</body></html>`, referer)
}

// User-Agent header XSS
func userAgentXSS(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "(no user-agent)"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: User-Agent header reflected without escaping
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Headers - User-Agent</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XSS in User-Agent Header</h1>
<h2>Your browser:</h2>
<div>%s</div>
<p><small>VULNERABLE: User-Agent header reflected without escaping</small></p>
<p><small>Test with: curl -A "&lt;script&gt;alert(1)&lt;/script&gt;" URL</small></p>
<p><a href="/vulns/xss/headers/">Back to Header Tests</a></p>
</div>
</body></html>`, userAgent)
}

// Cookie XSS (display page)
func cookieXSS(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("xss_test")
	cookieValue := "(no cookie set)"
	if err == nil {
		cookieValue = cookie.Value
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Cookie value reflected without escaping
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Headers - Cookie</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XSS in Cookie Value</h1>
<h2>Your cookie value:</h2>
<div>%s</div>
<p><a href="/vulns/xss/headers/cookie/set?value=test">Set a test cookie</a></p>
<p><small>VULNERABLE: Cookie value reflected without escaping</small></p>
<p><small>Test: Set cookie to &lt;script&gt;alert(1)&lt;/script&gt;</small></p>
<p><a href="/vulns/xss/headers/">Back to Header Tests</a></p>
</div>
</body></html>`, cookieValue)
}

// Cookie set endpoint
func cookieSet(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	if value == "" {
		value = "default_value"
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "xss_test",
		Value:   value,
		Path:    "/vulns/xss/headers/",
		Expires: time.Now().Add(1 * time.Hour),
	})

	http.Redirect(w, r, "/vulns/xss/headers/cookie", http.StatusFound)
}

// X-Forwarded-For header XSS
func xForwardedForXSS(w http.ResponseWriter, r *http.Request) {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		xff = r.RemoteAddr
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: X-Forwarded-For header reflected without escaping
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Headers - X-Forwarded-For</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XSS in X-Forwarded-For Header</h1>
<h2>Your IP address:</h2>
<div>%s</div>
<p><small>VULNERABLE: X-Forwarded-For header reflected without escaping</small></p>
<p><small>Test with: curl -H "X-Forwarded-For: &lt;script&gt;alert(1)&lt;/script&gt;" URL</small></p>
<p><a href="/vulns/xss/headers/">Back to Header Tests</a></p>
</div>
</body></html>`, xff)
}

// Accept-Language header XSS
func acceptLanguageXSS(w http.ResponseWriter, r *http.Request) {
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang == "" {
		acceptLang = "(no Accept-Language)"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Accept-Language header reflected without escaping
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Headers - Accept-Language</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XSS in Accept-Language Header</h1>
<h2>Your language preference:</h2>
<div>%s</div>
<p><small>VULNERABLE: Accept-Language header reflected without escaping</small></p>
<p><small>Test with: curl -H "Accept-Language: &lt;script&gt;alert(1)&lt;/script&gt;" URL</small></p>
<p><a href="/vulns/xss/headers/">Back to Header Tests</a></p>
</div>
</body></html>`, acceptLang)
}

// FP - Headers properly escaped
func fpEscaped(w http.ResponseWriter, r *http.Request) {
	referer := html.EscapeString(r.Header.Get("Referer"))
	userAgent := html.EscapeString(r.Header.Get("User-Agent"))
	xff := html.EscapeString(r.Header.Get("X-Forwarded-For"))

	if referer == "" {
		referer = "(none)"
	}
	if xff == "" {
		xff = html.EscapeString(r.RemoteAddr)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Headers - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XSS Headers - Safe (Properly Escaped)</h1>
<h2>Request headers:</h2>
<ul>
    <li><strong>Referer:</strong> %s</li>
    <li><strong>User-Agent:</strong> %s</li>
    <li><strong>X-Forwarded-For:</strong> %s</li>
</ul>
<p><small>SAFE: All headers are HTML-escaped before output</small></p>
<p><a href="/vulns/xss/headers/">Back to Header Tests</a></p>
</div>
</body></html>`, referer, userAgent, xff)
}
