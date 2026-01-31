package reflected

import (
	"fmt"
	"html"
	"html/template"
	"net/http"

	"github.com/subzerodev/hive/handlers"
	"github.com/subzerodev/hive/templates"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/xss/reflected/html-body", htmlBody)
		handlers.Handle("/vulns/xss/reflected/attribute", attribute)
		handlers.Handle("/vulns/xss/reflected/javascript", javascript)
		handlers.Handle("/vulns/xss/reflected/fp/escaped", fpEscaped)
	})
}

func htmlBody(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html")
	templates.Render(w, "xss/reflected/html-body", templates.Page{
		Title:     "Reflected XSS - HTML Body",
		Heading:   "Reflected XSS - HTML Body",
		FormValue: html.EscapeString(name),
		OutputRaw: template.HTML(name), // VULNERABLE: unescaped
	})
}

func attribute(w http.ResponseWriter, r *http.Request) {
	color := r.URL.Query().Get("color")
	if color == "" {
		color = "blue"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Unescaped in attribute context
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Reflected XSS - Attribute</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1 style="color: %s">Colored Text</h1>
<form method="GET">
    <input name="color" value="%s" placeholder="Color">
    <button type="submit">Change Color</button>
</form>
<p><small>Try: red" onmouseover="alert(1)</small></p>
</div>
</body></html>`, color, html.EscapeString(color))
}

func javascript(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	if msg == "" {
		msg = "Hello"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Unescaped in JavaScript context
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Reflected XSS - JavaScript</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Message Display</h1>
<form method="GET">
    <input name="msg" value="%s" placeholder="Message">
    <button type="submit">Show Message</button>
</form>
<script>
var message = "%s";
document.write("<p>" + message + "</p>");
</script>
<p><small>Try: ";alert(1);//</small></p>
</div>
</body></html>`, html.EscapeString(msg), msg)
}

func fpEscaped(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html")
	// SAFE: Properly escaped
	escaped := html.EscapeString(name)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Reflected XSS - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Welcome, %s!</h1>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<p><small>Input is properly escaped</small></p>
</div>
</body></html>`, escaped, escaped)
}
