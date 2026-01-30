package formpost

import (
	"fmt"
	"net/http"
	"time"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth/form-post/login", login)
		handlers.Handle("/vulns/auth/form-post/dashboard", dashboard)
		handlers.Handle("/vulns/auth/form-post/logout", logout)
		handlers.Handle("/vulns/auth/form-post/session", session)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "admin" && password == "password" {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_formpost",
				Value:    "authenticated_admin",
				Path:     "/",
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
			})
			http.Redirect(w, r, "/vulns/auth/form-post/dashboard", http.StatusFound)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body>
<h1>Login Failed</h1>
<p>Invalid credentials. Try admin / password</p>
<a href="/vulns/auth/form-post/login">Try again</a>
</body></html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Form POST Login</title></head>
<body>
<h1>Form POST Login</h1>
<form method="POST" action="/vulns/auth/form-post/login">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>Credentials: admin / password</small></p>
</body></html>`)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_formpost")
	if err != nil || cookie.Value != "authenticated_admin" {
		http.Redirect(w, r, "/vulns/auth/form-post/login", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>Dashboard (Form POST Auth)</h1>
<p>Welcome, admin! You are authenticated via form POST.</p>
<p><a href="/vulns/auth/form-post/logout">Logout</a></p>
</body></html>`)
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "session_formpost",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})
	http.Redirect(w, r, "/vulns/auth/form-post/login", http.StatusFound)
}

func session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("session_formpost")
	if err == nil && cookie.Value == "authenticated_admin" {
		fmt.Fprintf(w, `{"authenticated":true,"user":"admin"}`)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"authenticated":false}`)
}
