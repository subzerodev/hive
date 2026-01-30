package passwordexposure

import (
	"fmt"
	"html"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth-session/password-exposure/in-get", inGet)
		handlers.Handle("/vulns/auth-session/password-exposure/in-response", inResponse)
		handlers.Handle("/vulns/auth-session/password-exposure/fp/hidden", fpHidden)
	})
}

func inGet(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = ""
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Password in GET request (visible in URL, logs, history)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password in GET</title></head>
<body>
<h1>Login (GET Request)</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>VULNERABLE: Password sent via GET parameter (visible in URL)</small></p>
</body></html>`, html.EscapeString(username))
}

func inResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		w.Header().Set("Content-Type", "text/html")
		// VULNERABLE: Password echoed in response
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password in Response</title></head>
<body>
<h1>Login Result</h1>
<p>Username: %s</p>
<p>Password: %s</p>
<p><small>VULNERABLE: Password reflected in response</small></p>
<p><a href="/vulns/auth-session/password-exposure/in-response">Back</a></p>
</body></html>`, html.EscapeString(username), html.EscapeString(password))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password in Response</title></head>
<body>
<h1>Login</h1>
<form method="POST">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>VULNERABLE: Password will be echoed in response</small></p>
</body></html>`)
}

func fpHidden(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")

		w.Header().Set("Content-Type", "text/html")
		// SAFE: Password not reflected
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Login Result</title></head>
<body>
<h1>Login Result</h1>
<p>Username: %s</p>
<p>Authentication successful.</p>
<p><small>SAFE: Password not reflected in response</small></p>
<p><a href="/vulns/auth-session/password-exposure/fp/hidden">Back</a></p>
</body></html>`, html.EscapeString(username))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Login - Safe</title></head>
<body>
<h1>Login (Safe)</h1>
<form method="POST">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>SAFE: Password sent via POST, not reflected in response</small></p>
</body></html>`)
}
