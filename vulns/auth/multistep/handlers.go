package multistep

import (
	"fmt"
	"net/http"
	"time"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth/multi-step/step1", step1)
		handlers.Handle("/vulns/auth/multi-step/step2", step2)
		handlers.Handle("/vulns/auth/multi-step/dashboard", dashboard)
		handlers.Handle("/vulns/auth/multi-step/session", session)
	})
}

func step1(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		if username == "admin" {
			http.SetCookie(w, &http.Cookie{
				Name:    "multistep_user",
				Value:   username,
				Path:    "/",
				Expires: time.Now().Add(10 * time.Minute),
			})
			http.Redirect(w, r, "/vulns/auth/multi-step/step2", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Invalid username</h1><a href="/vulns/auth/multi-step/step1">Try again</a></body></html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Multi-Step Login - Step 1</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Multi-Step Login - Step 1</h1>
<form method="POST">
    <input name="username" placeholder="Username"><br>
    <button type="submit">Next</button>
</form>
<p><small>Username: admin</small></p>
</div>
</body></html>`)
}

func step2(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("multistep_user")
	if err != nil || cookie.Value != "admin" {
		http.Redirect(w, r, "/vulns/auth/multi-step/step1", http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		password := r.FormValue("password")
		if password == "password" {
			http.SetCookie(w, &http.Cookie{
				Name:    "multistep_session",
				Value:   "authenticated",
				Path:    "/",
				Expires: time.Now().Add(24 * time.Hour),
			})
			http.Redirect(w, r, "/vulns/auth/multi-step/dashboard", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Invalid password</h1><a href="/vulns/auth/multi-step/step2">Try again</a></body></html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Multi-Step Login - Step 2</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Multi-Step Login - Step 2</h1>
<p>Welcome, %s. Please enter your password:</p>
<form method="POST">
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
<p><small>Password: password</small></p>
</div>
</body></html>`, cookie.Value)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("multistep_session")
	if err != nil || cookie.Value != "authenticated" {
		http.Redirect(w, r, "/vulns/auth/multi-step/step1", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Dashboard</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Dashboard (Multi-Step Auth)</h1>
<p>Successfully authenticated via multi-step flow.</p>
</div>
<script src="/static/js/navbar.js"></script>
</body></html>`)
}

func session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("multistep_session")
	if err == nil && cookie.Value == "authenticated" {
		fmt.Fprintf(w, `{"authenticated":true,"user":"admin"}`)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"authenticated":false}`)
}
