// vulns/injection/hpp/handlers.go
package hpp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Basic HPP - duplicate parameters
		handlers.Handle("/vulns/injection/hpp/basic", basic)
		// HPP in forms
		handlers.Handle("/vulns/injection/hpp/form", form)
		// HPP bypass WAF
		handlers.Handle("/vulns/injection/hpp/waf-bypass", wafBypass)
		// False positive - properly handled
		handlers.Handle("/vulns/injection/hpp/fp/handled", fpHandled)
	})
}

func basic(w http.ResponseWriter, r *http.Request) {
	// Go's URL.Query() returns all values for a parameter
	// Different backends handle duplicates differently:
	// - PHP: Uses last value
	// - ASP.NET: Joins with comma
	// - JSP/Tomcat: Uses first value
	// - Go: Returns slice of all values

	params := r.URL.Query()
	ids := params["id"]

	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HTTP Parameter Pollution - Basic</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP Parameter Pollution - Basic</h1>
<p>Different backends handle duplicate parameters differently</p>

<h2>Test URLs:</h2>
<ul>
    <li><a href="?id=1">Single: ?id=1</a></li>
    <li><a href="?id=1&id=2">Duplicate: ?id=1&id=2</a></li>
    <li><a href="?id=1&id=2&id=3">Multiple: ?id=1&id=2&id=3</a></li>
</ul>

<h2>Received Parameters:</h2>
<pre id="output">`)

	if len(ids) > 0 {
		fmt.Fprintf(w, "All 'id' values: %v\n", ids)
		fmt.Fprintf(w, "First value (JSP/Tomcat style): %s\n", ids[0])
		fmt.Fprintf(w, "Last value (PHP style): %s\n", ids[len(ids)-1])
		fmt.Fprintf(w, "Joined (ASP.NET style): %s\n", strings.Join(ids, ","))
	} else {
		fmt.Fprintf(w, "No 'id' parameter provided")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: ?id=1&id=2 to see how duplicates are handled</small></p>
<p><small>Bypass: ?id=valid&id=malicious may bypass validation on first value</small></p>
<p><a href="/vulns/injection/hpp/">Back to HPP Tests</a></p>
</div>
</body></html>`)
}

func form(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	if r.Method == "POST" {
		r.ParseForm()
		amounts := r.Form["amount"]
		recipients := r.Form["recipient"]

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HTTP Parameter Pollution - Form</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP Parameter Pollution - Form (Transfer)</h1>
<h2>Transfer Details:</h2>
<pre id="output">`)

		// VULNERABLE: Uses first value for validation, last for execution
		if len(amounts) > 0 && len(recipients) > 0 {
			// Validation uses first value
			validationAmount := amounts[0]
			validationRecipient := recipients[0]
			fmt.Fprintf(w, "Validation (first value):\n  Amount: %s\n  Recipient: %s\n\n", validationAmount, validationRecipient)

			// Execution uses last value
			executionAmount := amounts[len(amounts)-1]
			executionRecipient := recipients[len(recipients)-1]
			fmt.Fprintf(w, "Execution (last value):\n  Amount: %s\n  Recipient: %s\n", executionAmount, executionRecipient)

			if validationAmount != executionAmount || validationRecipient != executionRecipient {
				fmt.Fprintf(w, "\n[!] HPP DETECTED: Different values used!")
			}
		}

		fmt.Fprintf(w, `</pre>
<p><a href="/vulns/injection/hpp/form">Try again</a></p>
<p><a href="/vulns/injection/hpp/">Back to HPP Tests</a></p>
</div>
</body></html>`)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HTTP Parameter Pollution - Form</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP Parameter Pollution - Form (Transfer)</h1>
<p>Hidden fields can be overridden with duplicate parameters</p>
<form method="POST">
    <input type="hidden" name="amount" value="10">
    <input type="hidden" name="recipient" value="merchant">
    Amount: <input name="amount" placeholder="Override amount"><br><br>
    Recipient: <input name="recipient" placeholder="Override recipient"><br><br>
    <button type="submit">Transfer</button>
</form>
<h3>Hint:</h3>
<p><small>The hidden fields set safe values, but your input can override them</small></p>
<p><a href="/vulns/injection/hpp/">Back to HPP Tests</a></p>
</div>
</body></html>`)
}

func wafBypass(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	queries := params["q"]

	w.Header().Set("Content-Type", "text/html")

	// Simulated WAF that only checks first parameter
	wafBlocked := false
	if len(queries) > 0 {
		first := queries[0]
		if strings.Contains(strings.ToLower(first), "select") ||
			strings.Contains(strings.ToLower(first), "<script>") {
			wafBlocked = true
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HTTP Parameter Pollution - WAF Bypass</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP Parameter Pollution - WAF Bypass</h1>
<p>WAF only inspects the first parameter value</p>

<h2>Test:</h2>
<form method="GET">
    <input name="q" value="" placeholder="Search query">
    <button type="submit">Search</button>
</form>

<h2>Result:</h2>
<pre id="output">`)

	if len(queries) > 0 {
		fmt.Fprintf(w, "All 'q' values: %v\n", queries)
		if wafBlocked {
			fmt.Fprintf(w, "WAF Status: BLOCKED (malicious pattern in first value)\n")
		} else {
			fmt.Fprintf(w, "WAF Status: PASSED\n")
			// Application uses last value
			lastQuery := queries[len(queries)-1]
			fmt.Fprintf(w, "Search executed with: %s\n", lastQuery)
		}
	} else {
		fmt.Fprintf(w, "Enter a search query")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: ?q=safe&q=SELECT * FROM users</small></p>
<p><small>WAF checks first value (safe), app uses last value (malicious)</small></p>
<p><a href="/vulns/injection/hpp/">Back to HPP Tests</a></p>
</div>
</body></html>`)
}

func fpHandled(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Only use first value, reject if duplicates exist
	ids, hasDuplicates := params["id"]
	if len(ids) > 1 {
		hasDuplicates = true
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HTTP Parameter Pollution - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP Parameter Pollution - Safe</h1>

<h2>Test URLs:</h2>
<ul>
    <li><a href="?id=1">Single: ?id=1</a></li>
    <li><a href="?id=1&id=2">Duplicate: ?id=1&id=2</a></li>
</ul>

<h2>Result:</h2>
<pre id="output">`)

	if hasDuplicates && len(ids) > 1 {
		fmt.Fprintf(w, "Error: Duplicate parameters detected. Request rejected.")
	} else if len(ids) == 1 {
		fmt.Fprintf(w, "ID: %s (single value accepted)", ids[0])
	} else {
		fmt.Fprintf(w, "No 'id' parameter provided")
	}

	fmt.Fprintf(w, `</pre>
<h3>Security:</h3>
<p><small>SAFE: Rejects requests with duplicate parameters</small></p>
<p><a href="/vulns/injection/hpp/">Back to HPP Tests</a></p>
</div>
</body></html>`)
}
