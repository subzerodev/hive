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
		handlers.Handle("/vulns/auth-session/password-exposure/in-cookie", inCookie)
		handlers.Handle("/vulns/auth-session/password-exposure/autocomplete", autocomplete)
		handlers.Handle("/vulns/auth-session/password-exposure/fp/hidden", fpHidden)

		// Cleartext password submission
		handlers.Handle("/vulns/auth-session/password-exposure/cleartext", cleartext)
		handlers.Handle("/vulns/auth-session/password-exposure/insecure-form-post", insecureFormPost)
		handlers.Handle("/vulns/auth-session/password-exposure/fp/secure-form", fpSecureForm)
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
<head><title>Password in GET</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (GET Request)</h1>
<form method="GET">
    <input name="username" value="%s" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>VULNERABLE: Password sent via GET parameter (visible in URL)</small></p>
</div>
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
<head><title>Password in Response</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login Result</h1>
<p>Username: %s</p>
<p>Password: %s</p>
<p><small>VULNERABLE: Password reflected in response</small></p>
<p><a href="/vulns/auth-session/password-exposure/in-response">Back</a></p>
</div>
</body></html>`, html.EscapeString(username), html.EscapeString(password))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password in Response</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login</h1>
<form method="POST">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>VULNERABLE: Password will be echoed in response</small></p>
</div>
</body></html>`)
}

func inCookie(w http.ResponseWriter, r *http.Request) {
	password := r.URL.Query().Get("password")
	if password == "" {
		password = "secret123"
	}

	// VULNERABLE: Password stored in cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "user_password",
		Value: password,
		Path:  "/",
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Password in Cookie</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Password Stored in Cookie</h1>
<p>A cookie "user_password" has been set with the password.</p>
<p><small>VULNERABLE: Password stored in cookie</small></p>
</div>
</body></html>`)
}

func autocomplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Password field with autocomplete enabled
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Autocomplete Enabled</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (Autocomplete Enabled)</h1>
<form method="POST">
    <input name="username" placeholder="Username" autocomplete="on"><br>
    <input type="password" name="password" placeholder="Password" autocomplete="on"><br>
    <button type="submit">Login</button>
</form>
<p><small>VULNERABLE: Password field has autocomplete="on"</small></p>
</div>
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
<head><title>Login Result</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login Result</h1>
<p>Username: %s</p>
<p>Authentication successful.</p>
<p><small>SAFE: Password not reflected in response</small></p>
<p><a href="/vulns/auth-session/password-exposure/fp/hidden">Back</a></p>
</div>
</body></html>`, html.EscapeString(username))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Login - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (Safe)</h1>
<form method="POST">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>SAFE: Password sent via POST, not reflected in response</small></p>
</div>
</body></html>`)
}

func cleartext(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Login form on HTTP page (cleartext submission)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Cleartext Password Submission</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (Cleartext Submission)</h1>
<p>This login form submits credentials over unencrypted HTTP.</p>

<form method="POST" action="http://localhost:8080/vulns/auth-session/password-exposure/cleartext">
    <input name="username" placeholder="Username"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <button type="submit">Login</button>
</form>

<h2>Issue:</h2>
<p>Credentials are submitted over HTTP (not HTTPS), allowing interception.</p>

<h3>Vulnerability:</h3>
<p><small>Cleartext submission of password - credentials can be sniffed</small></p>
<p><a href="/vulns/auth-session/password-exposure/">Back</a></p>
</div>
</body></html>`)
}

func insecureFormPost(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: HTTPS page with form posting to HTTP
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Insecure Form POST</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (Insecure Transition)</h1>
<p>This HTTPS page posts credentials to an HTTP endpoint.</p>

<form method="POST" action="http://insecure.example.com/login">
    <input name="username" placeholder="Username"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <button type="submit">Login</button>
</form>

<h2>Issue:</h2>
<p>Form action uses HTTP instead of HTTPS (insecure transition).</p>

<h3>Vulnerability:</h3>
<p><small>HTTPS to HTTP form submission - credentials exposed in transit</small></p>
<p><a href="/vulns/auth-session/password-exposure/">Back</a></p>
</div>
</body></html>`)
}

func fpSecureForm(w http.ResponseWriter, r *http.Request) {
	// SAFE: HTTPS form posting to HTTPS
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Secure Form POST</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Login (Secure)</h1>
<p>This form submits credentials securely over HTTPS.</p>

<form method="POST" action="https://secure.example.com/login">
    <input name="username" placeholder="Username"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <button type="submit">Login</button>
</form>

<h3>Security:</h3>
<p><small>SAFE: Credentials submitted over encrypted HTTPS connection</small></p>
<p><a href="/vulns/auth-session/password-exposure/">Back</a></p>
</div>
</body></html>`)
}
