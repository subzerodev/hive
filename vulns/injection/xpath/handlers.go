// vulns/injection/xpath/handlers.go
package xpath

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Basic XPath injection
		handlers.Handle("/vulns/injection/xpath/basic", basic)
		// XPath authentication bypass
		handlers.Handle("/vulns/injection/xpath/auth", auth)
		// Blind XPath injection
		handlers.Handle("/vulns/injection/xpath/blind", blind)
		// False positive - parameterized
		handlers.Handle("/vulns/injection/xpath/fp/parameterized", fpParameterized)
	})
}

// Simulated XML data for XPath queries
var usersXML = `
<users>
    <user id="1">
        <username>admin</username>
        <password>admin123</password>
        <role>administrator</role>
    </user>
    <user id="2">
        <username>john</username>
        <password>john456</password>
        <role>user</role>
    </user>
    <user id="3">
        <username>jane</username>
        <password>jane789</password>
        <role>user</role>
    </user>
</users>
`

// Simulated XPath query results
func simulateXPath(query string) (string, bool) {
	// Simulate successful injection patterns
	if strings.Contains(query, "' or '1'='1") || strings.Contains(query, "' or 1=1 or '") {
		return "admin, john, jane", true
	}
	if strings.Contains(query, "admin") && !strings.Contains(query, "wrongpass") {
		return "admin", true
	}
	if strings.Contains(query, "' or ''='") {
		return "admin, john, jane", true
	}
	// Normal query
	if strings.Contains(query, "john") {
		return "john", true
	}
	return "", false
}

func basic(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "john"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User input concatenated into XPath query
	xpathQuery := fmt.Sprintf("//users/user[username='%s']", username)

	result, found := simulateXPath(xpathQuery)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XPath Injection - Basic</title></head>
<body>
<h1>XPath Injection - Basic</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:300px">
    <button type="submit">Search</button>
</form>
<h2>XPath Query:</h2>
<pre>%s</pre>
<h2>Result:</h2>
<pre id="output">`, username, xpathQuery)

	if found {
		fmt.Fprintf(w, "User found: %s", result)
	} else {
		fmt.Fprintf(w, "No user found")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: ' or '1'='1 or ' or ''='</small></p>
<p><a href="/vulns/injection/xpath/">Back to XPath Tests</a></p>
</body></html>`)
}

func auth(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = "wrongpass"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Authentication via XPath query
	xpathQuery := fmt.Sprintf("//users/user[username='%s' and password='%s']", username, password)

	result, found := simulateXPath(xpathQuery)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XPath Injection - Authentication</title></head>
<body>
<h1>XPath Injection - Authentication Bypass</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:200px">
    <input name="password" value="%s" placeholder="Password" style="width:200px">
    <button type="submit">Login</button>
</form>
<h2>XPath Query:</h2>
<pre>%s</pre>
<h2>Result:</h2>
<pre id="output">`, username, password, xpathQuery)

	if found {
		fmt.Fprintf(w, "Login successful! Welcome, %s", result)
	} else {
		fmt.Fprintf(w, "Login failed: Invalid username or password")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: username=' or '1'='1 and password=anything</small></p>
<p><small>Or: username=admin' or '1'='1 and password=anything</small></p>
<p><a href="/vulns/injection/xpath/">Back to XPath Tests</a></p>
</body></html>`)
}

func blind(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "admin"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Blind XPath injection (only shows if user exists)
	xpathQuery := fmt.Sprintf("//users/user[username='%s']", username)
	_, found := simulateXPath(xpathQuery)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XPath Injection - Blind</title></head>
<body>
<h1>XPath Injection - Blind</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:300px">
    <button type="submit">Check</button>
</form>
<h2>Result:</h2>
<pre id="output">`, username)

	if found {
		fmt.Fprintf(w, "User exists")
	} else {
		fmt.Fprintf(w, "User does not exist")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Blind injection: extract data character by character using substring()</small></p>
<p><small>Try: admin' and substring(password,1,1)='a' and '1'='1</small></p>
<p><a href="/vulns/injection/xpath/">Back to XPath Tests</a></p>
</body></html>`)
}

func fpParameterized(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "john"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Validate input (only allow alphanumeric)
	re := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !re.MatchString(username) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XPath Injection - Safe</title></head>
<body>
<h1>XPath Injection - Safe (Validated)</h1>
<h2>Error:</h2>
<p>Invalid username. Only alphanumeric characters allowed.</p>
<p><a href="/vulns/injection/xpath/fp/parameterized">Try again</a></p>
<p><a href="/vulns/injection/xpath/">Back to XPath Tests</a></p>
</body></html>`)
		return
	}

	xpathQuery := fmt.Sprintf("//users/user[username='%s']", username)
	result, found := simulateXPath(xpathQuery)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XPath Injection - Safe</title></head>
<body>
<h1>XPath Injection - Safe (Validated)</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:300px">
    <button type="submit">Search</button>
</form>
<h2>XPath Query:</h2>
<pre>%s</pre>
<h2>Result:</h2>
<pre id="output">`, username, xpathQuery)

	if found {
		fmt.Fprintf(w, "User found: %s", result)
	} else {
		fmt.Fprintf(w, "No user found")
	}

	fmt.Fprintf(w, `</pre>
<h3>Filter:</h3>
<p><small>SAFE: Only alphanumeric characters allowed in username</small></p>
<p><a href="/vulns/injection/xpath/">Back to XPath Tests</a></p>
</body></html>`)
}
