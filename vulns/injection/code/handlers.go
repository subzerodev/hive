// vulns/injection/code/handlers.go
package code

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Simulated eval() injection (various languages)
		handlers.Handle("/vulns/injection/code/eval-js", evalJS)
		handlers.Handle("/vulns/injection/code/eval-php", evalPHP)
		handlers.Handle("/vulns/injection/code/eval-python", evalPython)
		// Expression evaluation
		handlers.Handle("/vulns/injection/code/expression", expression)
		// False positive - input validated
		handlers.Handle("/vulns/injection/code/fp/validated", fpValidated)
	})
}

// evalJS simulates JavaScript eval() injection
func evalJS(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "2+2"
	}

	w.Header().Set("Content-Type", "text/html")

	// Simulate vulnerable eval pattern (reflects code showing it would be executed)
	result := code
	// Simple math evaluation for demo
	if code == "2+2" {
		result = "4"
	} else if code == "7*7" {
		result = "49"
	} else if strings.Contains(code, "alert") || strings.Contains(code, "require") {
		result = "[Code execution simulated]"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Code Injection - JavaScript eval()</title></head>
<body>
<h1>Code Injection - JavaScript eval()</h1>
<p>Simulates server-side JavaScript eval() vulnerability</p>
<form method="GET">
    <input name="code" value="%s" placeholder="JavaScript code" style="width:300px">
    <button type="submit">Execute</button>
</form>
<h2>Result:</h2>
<pre id="output">eval("%s") = %s</pre>
<h3>Hint:</h3>
<p><small>Try: require('child_process').execSync('id') or process.env</small></p>
<p><a href="/vulns/injection/code/">Back to Code Injection Tests</a></p>
</body></html>`, code, code, result)
}

// evalPHP simulates PHP eval() injection
func evalPHP(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "2+2"
	}

	w.Header().Set("Content-Type", "text/html")

	result := code
	if code == "2+2" {
		result = "4"
	} else if strings.Contains(code, "system") || strings.Contains(code, "exec") || strings.Contains(code, "passthru") {
		result = "[Command execution simulated]"
	} else if strings.Contains(code, "file_get_contents") || strings.Contains(code, "include") {
		result = "[File operation simulated]"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Code Injection - PHP eval()</title></head>
<body>
<h1>Code Injection - PHP eval()</h1>
<p>Simulates PHP eval() vulnerability</p>
<form method="GET">
    <input name="code" value="%s" placeholder="PHP code" style="width:300px">
    <button type="submit">Execute</button>
</form>
<h2>Result:</h2>
<pre id="output">&lt;?php eval("%s"); ?&gt; = %s</pre>
<h3>Hint:</h3>
<p><small>Try: system('id') or file_get_contents('/etc/passwd')</small></p>
<p><a href="/vulns/injection/code/">Back to Code Injection Tests</a></p>
</body></html>`, code, code, result)
}

// evalPython simulates Python eval()/exec() injection
func evalPython(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "2+2"
	}

	w.Header().Set("Content-Type", "text/html")

	result := code
	if code == "2+2" {
		result = "4"
	} else if code == "__import__('os').system('id')" {
		result = "[Command execution simulated]"
	} else if strings.Contains(code, "__import__") || strings.Contains(code, "os.") || strings.Contains(code, "subprocess") {
		result = "[Code execution simulated]"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Code Injection - Python eval()</title></head>
<body>
<h1>Code Injection - Python eval()</h1>
<p>Simulates Python eval()/exec() vulnerability</p>
<form method="GET">
    <input name="code" value="%s" placeholder="Python code" style="width:300px">
    <button type="submit">Execute</button>
</form>
<h2>Result:</h2>
<pre id="output">eval("%s") = %s</pre>
<h3>Hint:</h3>
<p><small>Try: __import__('os').system('id') or open('/etc/passwd').read()</small></p>
<p><a href="/vulns/injection/code/">Back to Code Injection Tests</a></p>
</body></html>`, code, code, result)
}

// expression evaluates simple math expressions (simulates vulnerable expression parser)
func expression(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	if expr == "" {
		expr = "2+2"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Expression evaluation (simulated)
	result := evaluateExpression(expr)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Code Injection - Expression</title></head>
<body>
<h1>Code Injection - Expression Evaluator</h1>
<p>Evaluates mathematical expressions (vulnerable to code injection)</p>
<form method="GET">
    <input name="expr" value="%s" placeholder="Expression" style="width:300px">
    <button type="submit">Calculate</button>
</form>
<h2>Result:</h2>
<pre id="output">%s = %s</pre>
<h3>Hint:</h3>
<p><small>Try: 7*7 or expressions with special characters</small></p>
<p><a href="/vulns/injection/code/">Back to Code Injection Tests</a></p>
</body></html>`, expr, expr, result)
}

func evaluateExpression(expr string) string {
	// Simple expression evaluation for demo
	// Matches patterns like "7*7", "2+2", "10-3", "20/4"
	re := regexp.MustCompile(`^(\d+)\s*([+\-*/])\s*(\d+)$`)
	matches := re.FindStringSubmatch(expr)
	if len(matches) == 4 {
		a, _ := strconv.Atoi(matches[1])
		b, _ := strconv.Atoi(matches[3])
		op := matches[2]
		switch op {
		case "+":
			return strconv.Itoa(a + b)
		case "-":
			return strconv.Itoa(a - b)
		case "*":
			return strconv.Itoa(a * b)
		case "/":
			if b != 0 {
				return strconv.Itoa(a / b)
			}
			return "division by zero"
		}
	}
	// Return the expression if not simple math (simulates that arbitrary code would be eval'd)
	return "[evaluated: " + expr + "]"
}

// fpValidated - False positive: input is validated to numbers only
func fpValidated(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "2+2"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Only allow digits, +, -, *, /, spaces
	re := regexp.MustCompile(`^[\d\s+\-*/().]+$`)
	if !re.MatchString(code) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Code Injection - Safe</title></head>
<body>
<h1>Code Injection - Safe (Validated)</h1>
<h2>Error:</h2>
<pre>Invalid characters detected. Only numbers and basic math operators allowed.</pre>
<p><a href="/vulns/injection/code/fp/validated">Try again</a></p>
<p><a href="/vulns/injection/code/">Back to Code Injection Tests</a></p>
</body></html>`)
		return
	}

	result := evaluateExpression(code)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Code Injection - Safe</title></head>
<body>
<h1>Code Injection - Safe (Validated)</h1>
<p>Only allows numbers and basic math operators</p>
<form method="GET">
    <input name="code" value="%s" placeholder="Math expression" style="width:300px">
    <button type="submit">Calculate</button>
</form>
<h2>Result:</h2>
<pre id="output">%s = %s</pre>
<h3>Filter:</h3>
<p><small>SAFE: Only digits and math operators (+, -, *, /) allowed</small></p>
<p><a href="/vulns/injection/code/">Back to Code Injection Tests</a></p>
</body></html>`, code, code, result)
}
