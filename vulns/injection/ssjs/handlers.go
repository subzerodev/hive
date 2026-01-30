// vulns/injection/ssjs/handlers.go
package ssjs

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/ssjs/eval", evalInjection)
		handlers.Handle("/vulns/injection/ssjs/function", functionInjection)
		handlers.Handle("/vulns/injection/ssjs/settimeout", setTimeoutInjection)
		handlers.Handle("/vulns/injection/ssjs/fp/safe", fpSafe)
	})
}

func evalInjection(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("code")
	if input == "" {
		input = "1+1"
	}

	// Simulate server-side JavaScript eval vulnerability
	// In real Node.js this would be: eval(input)
	result := "2" // Simulated result
	if strings.Contains(input, "process") {
		result = "process.env revealed"
	} else if strings.Contains(input, "require") {
		result = "module loaded"
	} else if strings.Contains(input, "child_process") {
		result = "command execution possible"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Server-Side JavaScript Injection - eval</title></head>
<body>
<h1>Server-Side JavaScript Injection (eval)</h1>
<p>User input passed to eval() function.</p>

<form method="GET">
    <label>Expression:</label><br>
    <input name="code" value="%s" style="width:400px"><br><br>
    <button type="submit">Evaluate</button>
</form>

<h2>Simulated Execution:</h2>
<pre>eval("%s")</pre>

<h2>Result:</h2>
<pre>%s</pre>

<h2>Payloads to try:</h2>
<ul>
    <li><code>process.env</code> - Access environment variables</li>
    <li><code>require('fs').readFileSync('/etc/passwd')</code> - Read files</li>
    <li><code>require('child_process').execSync('id')</code> - Execute commands</li>
</ul>

<h3>Vulnerability:</h3>
<p><small>Server-side JavaScript code injection via eval()</small></p>
<p><a href="/vulns/injection/ssjs/">Back</a></p>
</body></html>`, input, input, result)
}

func functionInjection(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("body")
	if input == "" {
		input = "return 42"
	}

	// Simulate Function constructor injection
	// In real Node.js: new Function(input)()
	result := "42"
	if strings.Contains(input, "process") || strings.Contains(input, "global") {
		result = "global object accessed"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Server-Side JavaScript - Function Constructor</title></head>
<body>
<h1>Server-Side JavaScript Injection (Function)</h1>
<p>User input passed to Function constructor.</p>

<form method="GET">
    <label>Function body:</label><br>
    <input name="body" value="%s" style="width:400px"><br><br>
    <button type="submit">Execute</button>
</form>

<h2>Simulated Execution:</h2>
<pre>new Function("%s")()</pre>

<h2>Result:</h2>
<pre>%s</pre>

<h2>Payloads:</h2>
<ul>
    <li><code>return this.constructor.constructor('return process')().env</code></li>
    <li><code>return global.process.mainModule.require('child_process').execSync('id')</code></li>
</ul>

<h3>Vulnerability:</h3>
<p><small>Code injection via Function constructor</small></p>
<p><a href="/vulns/injection/ssjs/">Back</a></p>
</body></html>`, input, input, result)
}

func setTimeoutInjection(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("callback")
	if input == "" {
		input = "console.log('hello')"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Server-Side JavaScript - setTimeout</title></head>
<body>
<h1>Server-Side JavaScript Injection (setTimeout)</h1>
<p>User input passed to setTimeout with string argument.</p>

<form method="GET">
    <label>Callback code:</label><br>
    <input name="callback" value="%s" style="width:400px"><br><br>
    <button type="submit">Schedule</button>
</form>

<h2>Simulated Execution:</h2>
<pre>setTimeout("%s", 1000)</pre>

<h2>Note:</h2>
<p>When setTimeout/setInterval receive a string, it's evaluated like eval().</p>

<h3>Vulnerability:</h3>
<p><small>Code injection via setTimeout string argument</small></p>
<p><a href="/vulns/injection/ssjs/">Back</a></p>
</body></html>`, input, input)
}

func fpSafe(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("value")
	if input == "" {
		input = "42"
	}

	// SAFE: Input used as data, not code
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Safe JavaScript Handling</title></head>
<body>
<h1>Safe Server-Side JavaScript</h1>
<p>User input treated as data, not code.</p>

<form method="GET">
    <input name="value" value="%s" style="width:200px">
    <button type="submit">Submit</button>
</form>

<h2>Processing:</h2>
<pre>const userValue = sanitize(input);
const result = parseInt(userValue, 10) || 0;</pre>

<h2>Result:</h2>
<pre>%s</pre>

<h3>Security:</h3>
<p><small>SAFE: Input is validated and never executed as code</small></p>
<p><a href="/vulns/injection/ssjs/">Back</a></p>
</body></html>`, input, input)
}
