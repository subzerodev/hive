package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/subzerodev/hive/handlers"
)

var (
	codes   = make(map[string]bool)
	codesMu sync.RWMutex
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth/oauth/start", start)
		handlers.Handle("/vulns/auth/oauth/authorize", authorize)
		handlers.Handle("/vulns/auth/oauth/callback", callback)
		handlers.Handle("/vulns/auth/oauth/dashboard", dashboard)
		handlers.Handle("/vulns/auth/oauth/session", session)
	})
}

func start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>OAuth Login</title></head>
<body>
<h1>OAuth Login</h1>
<p>Login with our fake OAuth provider:</p>
<a href="/vulns/auth/oauth/authorize?client_id=hive&redirect_uri=/vulns/auth/oauth/callback">Login with HiveAuth</a>
<p><small>Credentials: admin / password</small></p>
</body></html>`)
}

func authorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "admin" && password == "password" {
			codeBytes := make([]byte, 16)
			rand.Read(codeBytes)
			code := hex.EncodeToString(codeBytes)

			codesMu.Lock()
			codes[code] = true
			codesMu.Unlock()

			http.Redirect(w, r, redirectURI+"?code="+code, http.StatusFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HiveAuth - Authorize</title></head>
<body>
<h1>HiveAuth - Authorize</h1>
<p>HIVE App wants to access your account</p>
<form method="POST">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Authorize</button>
</form>
</body></html>`)
}

func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	codesMu.RLock()
	valid := codes[code]
	codesMu.RUnlock()

	if !valid {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Invalid code</h1><a href="/vulns/auth/oauth/start">Try again</a></body></html>`)
		return
	}

	codesMu.Lock()
	delete(codes, code)
	codesMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:    "oauth_session",
		Value:   "authenticated_oauth",
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})
	http.Redirect(w, r, "/vulns/auth/oauth/dashboard", http.StatusFound)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("oauth_session")
	if err != nil || cookie.Value != "authenticated_oauth" {
		http.Redirect(w, r, "/vulns/auth/oauth/start", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>Dashboard (OAuth)</h1>
<p>Successfully authenticated via OAuth flow.</p>
</body></html>`)
}

func session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("oauth_session")
	if err == nil && cookie.Value == "authenticated_oauth" {
		fmt.Fprintf(w, `{"authenticated":true,"user":"admin"}`)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"authenticated":false}`)
}
