// vulns/misc/handlers.go
package misc

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Password autocomplete
		handlers.Handle("/vulns/misc/password-autocomplete", passwordAutocomplete)
		handlers.Handle("/vulns/misc/password-autocomplete/fp", passwordAutocompleteFP)

		// Duplicate cookies
		handlers.Handle("/vulns/misc/duplicate-cookies", duplicateCookies)
		handlers.Handle("/vulns/misc/duplicate-cookies/fp", duplicateCookiesFP)

		// Path-relative stylesheet
		handlers.Handle("/vulns/misc/path-relative-css", pathRelativeCSS)
		handlers.Handle("/vulns/misc/path-relative-css/fp", pathRelativeCSSFP)

		// Referer-dependent response
		handlers.Handle("/vulns/misc/referer-dependent", refererDependent)

		// User-agent dependent response
		handlers.Handle("/vulns/misc/useragent-dependent", useragentDependent)
		handlers.Handle("/vulns/misc/useragent-reflected", useragentReflected)

		// Cacheable sensitive response
		handlers.Handle("/vulns/misc/cacheable-https", cacheableHTTPS)
		handlers.Handle("/vulns/misc/cacheable-https/fp", cacheableHTTPSFP)

		// Cross-domain script include
		handlers.Handle("/vulns/misc/cross-domain-script", crossDomainScript)

		// Vulnerable JS library
		handlers.Handle("/vulns/misc/vulnerable-js", vulnerableJS)

		// Input reflected in response
		handlers.Handle("/vulns/misc/input-reflected", inputReflected)
		handlers.Handle("/vulns/misc/input-reflected-header", inputReflectedHeader)

		// Base64 encoded data in parameter
		handlers.Handle("/vulns/misc/base64-param", base64Param)
		handlers.Handle("/vulns/misc/base64-param-post", base64ParamPost)

		// Suspicious input transformation
		handlers.Handle("/vulns/misc/input-transformation", inputTransformation)

		// Big redirect (large redirect response)
		handlers.Handle("/vulns/misc/big-redirect", bigRedirect)
	})
}

func passwordAutocomplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password Autocomplete Enabled</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Password Field with Autocomplete Enabled</h1>
<p>Password field allows browser autocomplete (security risk).</p>

<form method="POST" action="/vulns/misc/login">
    <label>Username:</label><br>
    <input type="text" name="username" autocomplete="username"><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" autocomplete="current-password"><br><br>
    <button type="submit">Login</button>
</form>

<h3>Vulnerability:</h3>
<p><small>autocomplete="current-password" allows browsers to store credentials</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func passwordAutocompleteFP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password Autocomplete Disabled</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Password Field with Autocomplete Disabled</h1>
<p>Password field has autocomplete disabled.</p>

<form method="POST" action="/vulns/misc/login" autocomplete="off">
    <label>Username:</label><br>
    <input type="text" name="username" autocomplete="off"><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" autocomplete="off"><br><br>
    <button type="submit">Login</button>
</form>

<h3>Security:</h3>
<p><small>SAFE: autocomplete="off" prevents browser credential storage</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func duplicateCookies(w http.ResponseWriter, r *http.Request) {
	// Set duplicate cookies with different values
	w.Header().Add("Set-Cookie", "session=abc123; Path=/")
	w.Header().Add("Set-Cookie", "session=xyz789; Path=/vulns/")
	w.Header().Add("Set-Cookie", "auth=token1; Path=/")
	w.Header().Add("Set-Cookie", "auth=token2; Path=/vulns/misc/")
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Duplicate Cookies</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Duplicate Cookies Set</h1>
<p>Multiple cookies with same name but different paths.</p>

<h2>Cookies Set:</h2>
<pre>
Set-Cookie: session=abc123; Path=/
Set-Cookie: session=xyz789; Path=/vulns/
Set-Cookie: auth=token1; Path=/
Set-Cookie: auth=token2; Path=/vulns/misc/
</pre>

<h3>Vulnerability:</h3>
<p><small>Duplicate cookies can cause session fixation or confusion</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func duplicateCookiesFP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure")
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Single Cookie</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Single Cookie Set</h1>
<p>Only one session cookie with proper flags.</p>

<h2>Cookie Set:</h2>
<pre>Set-Cookie: session=abc123; Path=/; HttpOnly; Secure</pre>

<h3>Security:</h3>
<p><small>SAFE: Single cookie with HttpOnly and Secure flags</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func pathRelativeCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Path-Relative CSS</title>
    <link rel="stylesheet" href="/static/css/hive.css">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
<h1>Path-Relative Stylesheet Import</h1>
<p>Uses relative path for stylesheet which can be hijacked.</p>

<h2>Stylesheet:</h2>
<pre>&lt;link rel="stylesheet" href="style.css"&gt;</pre>

<h3>Vulnerability:</h3>
<p><small>Relative CSS paths can be hijacked via path confusion attacks</small></p>
<p><small>Example: /page/../../evil/style.css</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func pathRelativeCSSFP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Absolute CSS Path</title>
    <link rel="stylesheet" href="/static/css/hive.css">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="container">
<h1>Absolute Stylesheet Path</h1>
<p>Uses absolute path for stylesheet.</p>

<h2>Stylesheet:</h2>
<pre>&lt;link rel="stylesheet" href="/static/style.css"&gt;</pre>

<h3>Security:</h3>
<p><small>SAFE: Absolute paths prevent path confusion attacks</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func refererDependent(w http.ResponseWriter, r *http.Request) {
	referer := r.Header.Get("Referer")
	w.Header().Set("Content-Type", "text/html")

	content := "Standard content"
	if referer != "" && (referer == "http://admin.local/" || referer == "https://admin.internal/") {
		content = "ADMIN CONTENT - Database credentials: admin:secret123"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Referer-Dependent Response</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Referer-Dependent Response</h1>
<p>Content changes based on Referer header.</p>

<h2>Your Referer:</h2>
<pre>%s</pre>

<h2>Response Content:</h2>
<pre>%s</pre>

<h3>Vulnerability:</h3>
<p><small>Different content for internal referers may leak sensitive data</small></p>
<p><small>Try: curl -H "Referer: http://admin.local/" URL</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`, referer, content)
}

func useragentDependent(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	w.Header().Set("Content-Type", "text/html")

	content := "Standard content"
	if ua == "InternalBot/1.0" || ua == "AdminCrawler/2.0" {
		content = "INTERNAL CONTENT - API Key: sk-internal-12345"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>User-Agent Dependent Response</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User-Agent Dependent Response</h1>
<p>Content changes based on User-Agent header.</p>

<h2>Your User-Agent:</h2>
<pre>%s</pre>

<h2>Response Content:</h2>
<pre>%s</pre>

<h3>Vulnerability:</h3>
<p><small>Different content for specific user agents may leak data</small></p>
<p><small>Try: curl -A "InternalBot/1.0" URL</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`, ua, content)
}

func cacheableHTTPS(w http.ResponseWriter, r *http.Request) {
	// Sensitive response that is cacheable
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cacheable Sensitive Response</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Cacheable Sensitive Response</h1>
<p>This sensitive page can be cached by proxies.</p>

<h2>Sensitive Data:</h2>
<pre>
User: admin
API Key: sk-live-abc123
Account Balance: $10,000
</pre>

<h2>Cache Headers:</h2>
<pre>Cache-Control: public, max-age=3600</pre>

<h3>Vulnerability:</h3>
<p><small>Sensitive responses should not be publicly cacheable</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func cacheableHTTPSFP(w http.ResponseWriter, r *http.Request) {
	// Properly non-cacheable sensitive response
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Non-Cacheable Response</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Non-Cacheable Sensitive Response</h1>
<p>This sensitive page cannot be cached.</p>

<h2>Cache Headers:</h2>
<pre>
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0
</pre>

<h3>Security:</h3>
<p><small>SAFE: Proper cache headers prevent sensitive data caching</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func crossDomainScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Cross-Domain Script Include</title>
    <link rel="stylesheet" href="/static/css/hive.css">
    <script src="http://cdn.example.com/jquery-1.6.1.min.js"></script>
    <script src="https://untrusted-cdn.com/analytics.js"></script>
</head>
<body>
<div class="container">
<h1>Cross-Domain Script Include</h1>
<p>JavaScript loaded from external/untrusted domains.</p>

<h2>External Scripts:</h2>
<pre>
&lt;script src="http://cdn.example.com/jquery-1.6.1.min.js"&gt;&lt;/script&gt;
&lt;script src="https://untrusted-cdn.com/analytics.js"&gt;&lt;/script&gt;
</pre>

<h3>Vulnerabilities:</h3>
<ul>
    <li>HTTP script on HTTPS page (mixed content)</li>
    <li>Untrusted CDN could serve malicious code</li>
    <li>No SRI (Subresource Integrity) hashes</li>
</ul>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

// Input reflected in response (non-XSS detection)
func inputReflected(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test_value"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Input Reflected</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Input Returned in Response</h1>
<p>User input is reflected back in the response.</p>

<form method="GET">
    <input name="q" value="%s" style="width:300px">
    <button type="submit">Search</button>
</form>

<h2>Search Results for: %s</h2>
<p>No results found for "%s"</p>

<h3>Note:</h3>
<p><small>Input reflection may indicate potential for injection attacks</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`, input, input, input)
}

func inputReflectedHeader(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("callback")
	if input == "" {
		input = "jsonpCallback"
	}

	// Reflect input in custom header
	w.Header().Set("X-Callback", input)
	w.Header().Set("Content-Type", "application/javascript")
	fmt.Fprintf(w, `%s({"status":"ok","data":"test"});`, input)
}

func vulnerableJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable JavaScript Libraries</title>
    <link rel="stylesheet" href="/static/css/hive.css">
    <script src="/static/js/jquery-1.6.1.min.js"></script>
    <script src="/static/js/angular-1.4.0.js"></script>
    <script src="/static/js/lodash-3.10.0.js"></script>
</head>
<body>
<div class="container">
<h1>Vulnerable JavaScript Libraries Detected</h1>
<p>This page includes known vulnerable JavaScript libraries.</p>

<h2>Detected Libraries:</h2>
<table border="1" cellpadding="5">
    <tr><th>Library</th><th>Version</th><th>Known Vulnerabilities</th></tr>
    <tr><td>jQuery</td><td>1.6.1</td><td>XSS, Prototype Pollution</td></tr>
    <tr><td>AngularJS</td><td>1.4.0</td><td>XSS, Sandbox Escape</td></tr>
    <tr><td>Lodash</td><td>3.10.0</td><td>Prototype Pollution</td></tr>
</table>

<h3>Recommendation:</h3>
<p><small>Update to latest versions of all JavaScript libraries</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`)
}

func useragentReflected(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	w.Header().Set("Content-Type", "text/html")
	// Reflect user-agent directly (vulnerability: could be XSS if not escaped elsewhere)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>User-Agent Reflected</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User-Agent Dependent Response</h1>
<p>Your User-Agent is reflected in the response:</p>
<pre>%s</pre>
<p><small>VULNERABLE: User-Agent header reflected in response</small></p>
</div>
</body></html>`, ua)
}

func base64Param(w http.ResponseWriter, r *http.Request) {
	// Default base64 encoded sensitive data
	defaultData := base64.StdEncoding.EncodeToString([]byte(`{"user":"jamesmullen","admin":"1","countryCode":"IE","vuln":"true"}`))
	encoded := r.URL.Query().Get("data")
	if encoded == "" {
		encoded = defaultData
	}

	var decoded string
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded = "(invalid base64)"
	} else {
		decoded = string(decodedBytes)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Base64 Encoded Parameter</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Base64 Encoded Data in Parameter</h1>
<form method="GET">
    <button type="submit" name="data" value="%s">Submit</button>
</form>

<h2>Encoded:</h2>
<pre>%s</pre>

<h2>Decoded:</h2>
<pre>%s</pre>

<h3>Vulnerability:</h3>
<p><small>Base64 encoded data may contain sensitive information</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`, defaultData, encoded, decoded)
}

func base64ParamPost(w http.ResponseWriter, r *http.Request) {
	defaultData := base64.StdEncoding.EncodeToString([]byte(`{"session":"admin_session","token":"secret_token_123"}`))

	if r.Method == "POST" {
		r.ParseForm()
		encoded := r.FormValue("data")
		decodedBytes, _ := base64.StdEncoding.DecodeString(encoded)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Base64 POST Result</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Base64 Encoded Data (POST)</h1>
<h2>Received:</h2>
<pre>%s</pre>
<h2>Decoded:</h2>
<pre>%s</pre>
<p><a href="/vulns/misc/base64-param-post">Back</a></p>
</div>
</body></html>`, encoded, string(decodedBytes))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Base64 Encoded Parameter (POST)</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Base64 Encoded Data in POST Parameter</h1>
<form method="POST">
    <input type="hidden" name="data" value="%s">
    <button type="submit">Submit</button>
</form>
<h3>Vulnerability:</h3>
<p><small>Base64 encoded data in POST may contain sensitive information</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`, defaultData)
}

func inputTransformation(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	if input == "" {
		input = "%3Cscript%3Ealert(1)%3C/script%3E"
	}

	// VULNERABLE: Apply transformation that could enable attacks
	// Remove non-alphanumeric except %
	re := regexp.MustCompile(`[^a-zA-Z0-9%]`)
	transformed := re.ReplaceAllString(input, "")

	// URL decode the result
	decoded := transformed
	if d, err := urlDecode(transformed); err == nil {
		decoded = d
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Suspicious Input Transformation</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Suspicious Input Transformation</h1>
<form method="GET">
    <textarea name="input" style="width:300px;height:50px">%s</textarea><br>
    <button type="submit">Transform</button>
</form>

<h2>Input:</h2>
<pre>%s</pre>

<h2>After removing non-alphanumeric (except %%):</h2>
<pre>%s</pre>

<h2>After URL decoding:</h2>
<pre>%s</pre>

<h3>Vulnerability:</h3>
<p><small>Input transformations can enable filter bypasses</small></p>
<p><a href="/vulns/misc/">Back to Misc Tests</a></p>
</div>
</body></html>`, input, input, transformed, decoded)
}

func urlDecode(s string) (string, error) {
	result := strings.Builder{}
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			var val byte
			_, err := fmt.Sscanf(s[i:i+3], "%%%02x", &val)
			if err == nil {
				result.WriteByte(val)
				i += 3
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String(), nil
}

func bigRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "http://example.com/"
	}

	// Generate large response body before redirect
	w.Header().Set("Location", target)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusFound)

	// Large body in redirect response (unusual, potential for cache poisoning)
	body := strings.Repeat("A", 10000)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Redirecting...</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Redirecting to %s</h1>
<p>Please wait...</p>
<div style="display:none">%s</div>
</div>
</body></html>`, target, body)
}
