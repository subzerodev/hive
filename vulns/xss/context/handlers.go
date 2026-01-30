package context

import (
	"fmt"
	"html"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Different XSS contexts
		handlers.Handle("/vulns/xss/context/svg", svgContext)
		handlers.Handle("/vulns/xss/context/data-attr", dataAttrContext)
		handlers.Handle("/vulns/xss/context/css-style", cssStyleContext)
		handlers.Handle("/vulns/xss/context/css-expression", cssExpressionContext)
		handlers.Handle("/vulns/xss/context/iframe-srcdoc", iframeSrcdocContext)
		handlers.Handle("/vulns/xss/context/href", hrefContext)
		handlers.Handle("/vulns/xss/context/src", srcContext)
		handlers.Handle("/vulns/xss/context/html-comment", htmlCommentContext)
		handlers.Handle("/vulns/xss/context/js-comment", jsCommentContext)
		handlers.Handle("/vulns/xss/context/js-template", jsTemplateContext)

		// FP - Properly sanitized context
		handlers.Handle("/vulns/xss/context/fp/sanitized", fpSanitized)
	})
}

// SVG context XSS
func svgContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "red"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in SVG context
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - SVG</title></head>
<body>
<h1>XSS in SVG Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Color" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>SVG:</h2>
<svg width="200" height="100">
    <rect width="100%%" height="100%%" fill="%s"/>
    <text x="50%%" y="50%%" text-anchor="middle" fill="white">SVG</text>
</svg>
<p><small>Try: red" onload="alert(1)" or red"><script>alert(1)</script></small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// Data attribute context XSS
func dataAttrContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in data attribute, later used in JS
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - Data Attribute</title></head>
<body>
<h1>XSS in Data Attribute Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Data value" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="target" data-value="%s">Check console</div>
<script>
var el = document.getElementById('target');
var data = el.getAttribute('data-value');
document.write('<p>Data: ' + data + '</p>');
</script>
<p><small>Try: "><img src=x onerror=alert(1)> or test" onclick="alert(1)</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// CSS style context XSS
func cssStyleContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "blue"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in CSS style
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>XSS Context - CSS Style</title>
<style>
.user-style {
    color: %s;
}
</style>
</head>
<body>
<h1>XSS in CSS Style Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Color" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Styled text:</h2>
<p class="user-style">This text uses your color</p>
<p><small>Try: blue;}</style><script>alert(1)</script><style> or blue;background:url(javascript:alert(1))</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, input, html.EscapeString(input))
}

// CSS expression context (legacy IE, but still tested by scanners)
func cssExpressionContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "100px"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in CSS that could use expression() in IE
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - CSS Expression</title></head>
<body>
<h1>XSS in CSS Expression Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Width" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Styled element:</h2>
<div style="width: %s; height: 100px; background: lightblue;">Box</div>
<p><small>Try (IE only): expression(alert(1)) or 100px;background-image:url(javascript:alert(1))</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// iframe srcdoc context XSS
func iframeSrcdocContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "Hello"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in iframe srcdoc
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - iframe srcdoc</title></head>
<body>
<h1>XSS in iframe srcdoc Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Content" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>iframe:</h2>
<iframe srcdoc="<html><body>%s</body></html>" width="400" height="100"></iframe>
<p><small>Try: &lt;script&gt;alert(1)&lt;/script&gt; (HTML entities decoded in srcdoc)</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// href attribute context XSS
func hrefContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("url")
	if input == "" {
		input = "https://example.com"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in href attribute
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - href</title></head>
<body>
<h1>XSS in href Attribute Context</h1>
<form method="GET">
    <input name="url" value="%s" placeholder="URL" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Link:</h2>
<a href="%s">Click this link</a>
<p><small>Try: javascript:alert(1) or data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// src attribute context XSS
func srcContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("src")
	if input == "" {
		input = "/static/placeholder.png"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in src attribute
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - src</title></head>
<body>
<h1>XSS in src Attribute Context</h1>
<form method="GET">
    <input name="src" value="%s" placeholder="Image URL" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Image:</h2>
<img src="%s" alt="User image" onerror="this.alt='Image failed to load'">
<p><small>Try: x" onerror="alert(1) or javascript:alert(1)</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// HTML comment context XSS
func htmlCommentContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "user note"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in HTML comment
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - HTML Comment</title></head>
<body>
<h1>XSS in HTML Comment Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Note" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Page content:</h2>
<!-- User note: %s -->
<p>Check page source for comment</p>
<p><small>Try: -->&lt;script&gt;alert(1)&lt;/script&gt;&lt;!--</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// JavaScript comment context XSS
func jsCommentContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "user"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in JavaScript comment
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - JS Comment</title></head>
<body>
<h1>XSS in JavaScript Comment Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Username" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Page content:</h2>
<script>
// User: %s
var x = 1;
</script>
<p>Check page source for JS comment</p>
<p><small>Try: test&#10;alert(1)// (newline injection) or */alert(1)/*</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// JavaScript template literal context XSS
func jsTemplateContext(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "World"
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Input in JavaScript template literal
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - JS Template</title></head>
<body>
<h1>XSS in JavaScript Template Literal Context</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Name" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output"></div>
<script>
var name = ` + "`%s`" + `;
document.getElementById('output').innerHTML = ` + "`Hello, ${name}!`" + `;
</script>
<p><small>Try: ${alert(1)} or ${constructor.constructor('alert(1)')()}</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, html.EscapeString(input), input)
}

// FP - Properly sanitized
func fpSanitized(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	escaped := html.EscapeString(input)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Context - Safe</title></head>
<body>
<h1>XSS Context - Safe (Properly Escaped)</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Input" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div>%s</div>
<p><small>SAFE: All output is HTML-escaped</small></p>
<p><a href="/vulns/xss/context/">Back to Context Tests</a></p>
</body></html>`, escaped, escaped)
}
