// vulns/injection/ssti/handlers.go
package ssti

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"net/http"
	texttemplate "text/template"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Go text/template (vulnerable - allows function calls)
		handlers.Handle("/vulns/injection/ssti/go-text", goText)
		// Go html/template (safer but still exploitable in some cases)
		handlers.Handle("/vulns/injection/ssti/go-html", goHTML)
		// Simulated Jinja2-style (for scanner detection)
		handlers.Handle("/vulns/injection/ssti/jinja2", jinja2Style)
		// Simulated ERB-style
		handlers.Handle("/vulns/injection/ssti/erb", erbStyle)
		// False positive - properly escaped
		handlers.Handle("/vulns/injection/ssti/fp/escaped", fpEscaped)
	})
}

// goText demonstrates SSTI in Go's text/template
func goText(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSTI - Go text/template</title></head>
<body>
<h1>Server-Side Template Injection - Go text/template</h1>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">`, name)

	// VULNERABLE: User input used directly in template
	templateStr := fmt.Sprintf("Hello, %s!", name)
	tmpl, err := texttemplate.New("test").Parse(templateStr)
	if err != nil {
		fmt.Fprintf(w, "Template error: %s", err.Error())
	} else {
		var buf bytes.Buffer
		tmpl.Execute(&buf, nil)
		fmt.Fprintf(w, "%s", buf.String())
	}

	fmt.Fprintf(w, `</div>
<h3>Hint:</h3>
<p><small>Try: {{.}} or {{printf "%%s" "injected"}}</small></p>
<p><a href="/vulns/injection/ssti/">Back to SSTI Tests</a></p>
</body></html>`)
}

// goHTML demonstrates SSTI in Go's html/template (auto-escapes but still vulnerable to logic)
func goHTML(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSTI - Go html/template</title></head>
<body>
<h1>Server-Side Template Injection - Go html/template</h1>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">`, name)

	// VULNERABLE: User input in template string (html/template escapes HTML but template logic still works)
	templateStr := fmt.Sprintf("Hello, %s!", name)
	tmpl, err := htmltemplate.New("test").Parse(templateStr)
	if err != nil {
		fmt.Fprintf(w, "Template error: %s", err.Error())
	} else {
		var buf bytes.Buffer
		tmpl.Execute(&buf, nil)
		fmt.Fprintf(w, "%s", buf.String())
	}

	fmt.Fprintf(w, `</div>
<h3>Hint:</h3>
<p><small>Try: {{.}} (HTML is escaped but template directives work)</small></p>
<p><a href="/vulns/injection/ssti/">Back to SSTI Tests</a></p>
</body></html>`)
}

// jinja2Style simulates Jinja2 SSTI for scanner detection
func jinja2Style(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	if expr == "" {
		expr = "World"
	}

	w.Header().Set("Content-Type", "text/html")

	// Simulate vulnerable Jinja2-style template (reflects input without processing)
	// This allows scanners to detect SSTI patterns like {{7*7}}
	result := expr
	// Simple evaluation for demo purposes
	if expr == "{{7*7}}" {
		result = "49"
	} else if expr == "{{7*'7'}}" {
		result = "7777777"
	} else if expr == "${7*7}" {
		result = "49"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSTI - Jinja2 Style</title></head>
<body>
<h1>Server-Side Template Injection - Jinja2 Style</h1>
<form method="GET">
    <input name="expr" value="%s" placeholder="Expression" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">Hello, %s!</div>
<h3>Hint:</h3>
<p><small>Try: {{7*7}} or {{7*'7'}} or ${7*7}</small></p>
<p><a href="/vulns/injection/ssti/">Back to SSTI Tests</a></p>
</body></html>`, expr, result)
}

// erbStyle simulates ERB SSTI for scanner detection
func erbStyle(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	if expr == "" {
		expr = "World"
	}

	w.Header().Set("Content-Type", "text/html")

	result := expr
	// Simple evaluation for demo
	if expr == "<%=7*7%>" {
		result = "49"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSTI - ERB Style</title></head>
<body>
<h1>Server-Side Template Injection - ERB Style</h1>
<form method="GET">
    <input name="expr" value="%s" placeholder="Expression" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">Hello, %s!</div>
<h3>Hint:</h3>
<p><small>Try: &lt;%=7*7%&gt;</small></p>
<p><a href="/vulns/injection/ssti/">Back to SSTI Tests</a></p>
</body></html>`, expr, result)
}

// fpEscaped - False positive: input is escaped, not used in template
func fpEscaped(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Input is passed as data, not as template code
	tmpl := htmltemplate.Must(htmltemplate.New("safe").Parse(`Hello, {{.Name}}!`))
	var buf bytes.Buffer
	tmpl.Execute(&buf, map[string]string{"Name": name})

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSTI - Safe (Escaped)</title></head>
<body>
<h1>Server-Side Template Injection - Safe</h1>
<form method="GET">
    <input name="name" value="%s" placeholder="Your name" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">%s</div>
<h3>Filter:</h3>
<p><small>SAFE: Input passed as template data, not template code. HTML is auto-escaped.</small></p>
<p><a href="/vulns/injection/ssti/">Back to SSTI Tests</a></p>
</body></html>`, htmltemplate.HTMLEscapeString(name), buf.String())
}
