package reflected

import (
	"fmt"
	"html"
	"net/http"

	"github.com/subzerodev/hive/handlers"
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
	// VULNERABLE: Direct output without escaping
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Reflected XSS - HTML Body</title></head>
<body>
<h1>Welcome, %s!</h1>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<p><small>Try: &lt;script&gt;alert(1)&lt;/script&gt;</small></p>
</body></html>`, name, html.EscapeString(name))
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
<head><title>Reflected XSS - Attribute</title></head>
<body>
<h1 style="color: %s">Colored Text</h1>
<form method="GET">
    <input name="color" value="%s" placeholder="Color">
    <button type="submit">Change Color</button>
</form>
<p><small>Try: red" onmouseover="alert(1)</small></p>
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
<head><title>Reflected XSS - JavaScript</title></head>
<body>
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
<head><title>Reflected XSS - Safe</title></head>
<body>
<h1>Welcome, %s!</h1>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<p><small>Input is properly escaped</small></p>
</body></html>`, escaped, escaped)
}
