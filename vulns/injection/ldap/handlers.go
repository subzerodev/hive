// vulns/injection/ldap/handlers.go
package ldap

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/ldap/basic", basic)
		handlers.Handle("/vulns/injection/ldap/auth", auth)
		handlers.Handle("/vulns/injection/ldap/search", search)
		handlers.Handle("/vulns/injection/ldap/blind", blind)
		handlers.Handle("/vulns/injection/ldap/fp/escaped", fpEscaped)
	})
}

// Simulated LDAP query results
func simulateLDAP(filter string) ([]string, bool) {
	// Simulate injection patterns
	if strings.Contains(filter, "*") || strings.Contains(filter, ")(") {
		return []string{"admin", "user1", "user2", "guest"}, true
	}
	if strings.Contains(filter, "|") {
		return []string{"admin", "user1"}, true
	}
	if strings.Contains(filter, "admin") {
		return []string{"admin"}, true
	}
	if strings.Contains(filter, "user") {
		return []string{"user1"}, true
	}
	return nil, false
}

func basic(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "admin"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User input directly in LDAP filter
	ldapFilter := fmt.Sprintf("(&(uid=%s)(objectClass=person))", username)

	results, found := simulateLDAP(ldapFilter)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>LDAP Injection - Basic</title></head>
<body>
<h1>LDAP Injection - Basic</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:300px">
    <button type="submit">Search</button>
</form>
<h2>LDAP Filter:</h2>
<pre>%s</pre>
<h2>Results:</h2>
<pre id="output">`, username, ldapFilter)

	if found {
		fmt.Fprintf(w, "Found users: %s", strings.Join(results, ", "))
	} else {
		fmt.Fprintf(w, "No users found")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: * or admin)(|(uid=*) or admin)(&amp;)</small></p>
<p><a href="/vulns/injection/ldap/">Back to LDAP Tests</a></p>
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

	// VULNERABLE: Auth bypass via LDAP injection
	ldapFilter := fmt.Sprintf("(&(uid=%s)(userPassword=%s))", username, password)

	_, found := simulateLDAP(ldapFilter)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>LDAP Injection - Authentication</title></head>
<body>
<h1>LDAP Injection - Authentication Bypass</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:200px">
    <input name="password" value="%s" placeholder="Password" style="width:200px">
    <button type="submit">Login</button>
</form>
<h2>LDAP Filter:</h2>
<pre>%s</pre>
<h2>Result:</h2>
<pre id="output">`, username, password, ldapFilter)

	if found || strings.Contains(username, "*") || strings.Contains(password, "*") {
		fmt.Fprintf(w, "Login successful! Welcome, %s", username)
	} else {
		fmt.Fprintf(w, "Login failed: Invalid credentials")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: username=* password=* or username=admin)(|(password=*)</small></p>
<p><a href="/vulns/injection/ldap/">Back to LDAP Tests</a></p>
</body></html>`)
}

func search(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		query = "john"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: User search with LDAP injection
	ldapFilter := fmt.Sprintf("(|(cn=*%s*)(mail=*%s*))", query, query)

	results, _ := simulateLDAP(ldapFilter)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>LDAP Injection - Search</title></head>
<body>
<h1>LDAP Injection - User Search</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Search users" style="width:300px">
    <button type="submit">Search</button>
</form>
<h2>LDAP Filter:</h2>
<pre>%s</pre>
<h2>Results:</h2>
<pre id="output">`, query, ldapFilter)

	if len(results) > 0 {
		fmt.Fprintf(w, "Found: %s", strings.Join(results, ", "))
	} else {
		fmt.Fprintf(w, "No results")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Try: *)(objectClass=* or *)(&amp;(objectClass=*)</small></p>
<p><a href="/vulns/injection/ldap/">Back to LDAP Tests</a></p>
</body></html>`)
}

func blind(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "admin"
	}

	w.Header().Set("Content-Type", "text/html")

	ldapFilter := fmt.Sprintf("(uid=%s)", username)
	_, found := simulateLDAP(ldapFilter)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>LDAP Injection - Blind</title></head>
<body>
<h1>LDAP Injection - Blind</h1>
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
<p><small>Blind LDAP: Extract data character by character</small></p>
<p><small>Try: admin* or a* to enumerate</small></p>
<p><a href="/vulns/injection/ldap/">Back to LDAP Tests</a></p>
</body></html>`)
}

func fpEscaped(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "admin"
	}

	w.Header().Set("Content-Type", "text/html")

	// SAFE: Escape LDAP special characters
	re := regexp.MustCompile(`[\\*()|\x00]`)
	if re.MatchString(username) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>LDAP Injection - Safe</title></head>
<body>
<h1>LDAP Injection - Safe (Escaped)</h1>
<h2>Error:</h2>
<p>Invalid characters in username. Special characters not allowed.</p>
<p><a href="/vulns/injection/ldap/fp/escaped">Try again</a></p>
<p><a href="/vulns/injection/ldap/">Back to LDAP Tests</a></p>
</body></html>`)
		return
	}

	ldapFilter := fmt.Sprintf("(uid=%s)", username)
	results, found := simulateLDAP(ldapFilter)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>LDAP Injection - Safe</title></head>
<body>
<h1>LDAP Injection - Safe (Escaped)</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username" style="width:300px">
    <button type="submit">Search</button>
</form>
<h2>LDAP Filter:</h2>
<pre>%s</pre>
<h2>Results:</h2>
<pre id="output">`, username, ldapFilter)

	if found {
		fmt.Fprintf(w, "Found: %s", strings.Join(results, ", "))
	} else {
		fmt.Fprintf(w, "No user found")
	}

	fmt.Fprintf(w, `</pre>
<h3>Security:</h3>
<p><small>SAFE: LDAP special characters (*, (, ), |, \, NUL) are rejected</small></p>
<p><a href="/vulns/injection/ldap/">Back to LDAP Tests</a></p>
</body></html>`)
}
