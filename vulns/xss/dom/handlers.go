package dom

import (
	"fmt"
	"html"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/xss/dom/innerhtml", innerHTML)
		handlers.Handle("/vulns/xss/dom/document-write", documentWrite)
		handlers.Handle("/vulns/xss/dom/location", location)
		handlers.Handle("/vulns/xss/dom/fp/safe", fpSafe)
	})
}

func innerHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// DOM XSS - innerHTML sink
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>DOM XSS - innerHTML</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>DOM XSS - innerHTML</h1>
<div id="output"></div>
<form onsubmit="return false;">
    <input id="input" placeholder="Enter text">
    <button onclick="document.getElementById('output').innerHTML = document.getElementById('input').value;">Display</button>
</form>
<p><small>Try: &lt;img src=x onerror=alert(1)&gt;</small></p>
<script>
// VULNERABLE: Using innerHTML with user input from URL hash
if (location.hash) {
    document.getElementById('output').innerHTML = decodeURIComponent(location.hash.substring(1));
}
</script>
</div>
</body></html>`)
}

func documentWrite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// DOM XSS - document.write sink
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>DOM XSS - document.write</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>DOM XSS - document.write</h1>
<script>
// VULNERABLE: document.write with URL parameter
var params = new URLSearchParams(window.location.search);
var name = params.get('name') || 'Guest';
document.write('<p>Hello, ' + name + '!</p>');
</script>
<form method="GET">
    <input name="name" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<p><small>Try: &lt;script&gt;alert(1)&lt;/script&gt;</small></p>
</div>
</body></html>`)
}

func location(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// DOM XSS - location sink
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>DOM XSS - location</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>DOM XSS - Redirect</h1>
<form method="GET">
    <input name="url" placeholder="URL to redirect">
    <button type="submit">Go</button>
</form>
<script>
// VULNERABLE: Unvalidated redirect from URL parameter
var params = new URLSearchParams(window.location.search);
var url = params.get('url');
if (url) {
    // Open redirect vulnerability
    window.location = url;
}
</script>
<p><small>Try: javascript:alert(1)</small></p>
</div>
</body></html>`)
}

func fpSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html")
	escaped := html.EscapeString(name)
	// SAFE: Using textContent instead of innerHTML
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>DOM XSS - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>DOM XSS - Safe</h1>
<div id="output"></div>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<script>
// SAFE: Using textContent
document.getElementById('output').textContent = %q;
</script>
<p><small>Input is safely rendered using textContent</small></p>
</div>
</body></html>`, escaped, escaped)
}
