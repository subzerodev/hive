// vulns/injection/ssi/handlers.go
package ssi

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/ssi/basic", basic)
		handlers.Handle("/vulns/injection/ssi/exec", exec)
		handlers.Handle("/vulns/injection/ssi/include", include)
		handlers.Handle("/vulns/injection/ssi/fp/disabled", fpDisabled)
	})
}

// Simulate SSI processing
func processSSI(input string) string {
	result := input

	// Simulate <!--#echo --> directive
	if strings.Contains(input, "<!--#echo") {
		result = strings.Replace(result, "<!--#echo var=\"DATE_LOCAL\" -->", "Thu Jan 30 21:30:00 2026", -1)
		result = strings.Replace(result, "<!--#echo var=\"DOCUMENT_URI\" -->", "/vulns/injection/ssi/basic", -1)
		result = strings.Replace(result, "<!--#echo var=\"SERVER_SOFTWARE\" -->", "Apache/2.4.52", -1)
	}

	// Simulate <!--#exec --> directive
	if strings.Contains(input, "<!--#exec cmd=") {
		re := regexp.MustCompile(`<!--#exec cmd="([^"]*)"`)
		matches := re.FindStringSubmatch(input)
		if len(matches) > 1 {
			result = re.ReplaceAllString(result, "[COMMAND EXECUTED: "+matches[1]+"]")
		}
	}

	// Simulate <!--#include --> directive
	if strings.Contains(input, "<!--#include") {
		if strings.Contains(input, "/etc/passwd") {
			result = strings.Replace(result, input, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", -1)
		}
	}

	return result
}

func basic(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("text")
	if input == "" {
		input = "Hello World"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: SSI directives processed
	processed := processSSI(input)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSI Injection - Basic</title></head>
<body>
<h1>Server-Side Includes Injection - Basic</h1>
<form method="GET">
    <input name="text" value="%s" placeholder="Enter text" style="width:400px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<pre id="output">%s</pre>
<h3>Hint:</h3>
<p><small>Try: &lt;!--#echo var="DATE_LOCAL" --&gt;</small></p>
<p><small>Or: &lt;!--#echo var="SERVER_SOFTWARE" --&gt;</small></p>
<p><a href="/vulns/injection/ssi/">Back to SSI Tests</a></p>
</body></html>`, input, processed)
}

func exec(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("cmd")
	if input == "" {
		input = "<!--#exec cmd=\"id\" -->"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: SSI exec directive
	processed := processSSI(input)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSI Injection - Exec</title></head>
<body>
<h1>Server-Side Includes Injection - Command Execution</h1>
<form method="GET">
    <input name="cmd" value="%s" placeholder="SSI directive" style="width:400px">
    <button type="submit">Execute</button>
</form>
<h2>Output:</h2>
<pre id="output">%s</pre>
<h3>Hint:</h3>
<p><small>Try: &lt;!--#exec cmd="cat /etc/passwd" --&gt;</small></p>
<p><a href="/vulns/injection/ssi/">Back to SSI Tests</a></p>
</body></html>`, input, processed)
}

func include(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		file = "header.html"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: SSI include directive
	ssiDirective := fmt.Sprintf("<!--#include virtual=\"%s\" -->", file)
	processed := processSSI(ssiDirective)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSI Injection - Include</title></head>
<body>
<h1>Server-Side Includes Injection - File Include</h1>
<form method="GET">
    <input name="file" value="%s" placeholder="File to include" style="width:400px">
    <button type="submit">Include</button>
</form>
<h2>SSI Directive:</h2>
<pre>%s</pre>
<h2>Output:</h2>
<pre id="output">%s</pre>
<h3>Hint:</h3>
<p><small>Try: /etc/passwd or ../../../etc/passwd</small></p>
<p><a href="/vulns/injection/ssi/">Back to SSI Tests</a></p>
</body></html>`, file, ssiDirective, processed)
}

func fpDisabled(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("text")
	if input == "" {
		input = "Hello World"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: SSI directives are escaped, not processed
	escaped := strings.ReplaceAll(input, "<", "&lt;")
	escaped = strings.ReplaceAll(escaped, ">", "&gt;")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSI Injection - Safe</title></head>
<body>
<h1>Server-Side Includes - Safe (Disabled)</h1>
<form method="GET">
    <input name="text" value="%s" placeholder="Enter text" style="width:400px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<pre id="output">%s</pre>
<h3>Security:</h3>
<p><small>SAFE: SSI processing is disabled, directives are escaped</small></p>
<p><a href="/vulns/injection/ssi/">Back to SSI Tests</a></p>
</body></html>`, strings.ReplaceAll(input, "<", "&lt;"), escaped)
}
