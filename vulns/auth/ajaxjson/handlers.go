package ajaxjson

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth/ajax-json/login", login)
		handlers.Handle("/vulns/auth/ajax-json/api/user", apiUser)
		handlers.Handle("/vulns/auth/ajax-json/session", session)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error": "Invalid JSON"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if creds.Username == "admin" && creds.Password == "password" {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_ajax",
				Value:    "authenticated_admin",
				Path:     "/",
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
			})
			fmt.Fprintf(w, `{"success": true, "user": "admin"}`)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success": false, "error": "Invalid credentials"}`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>AJAX JSON Login</title></head>
<body>
<h1>AJAX JSON Login</h1>
<input id="username" placeholder="Username"><br>
<input type="password" id="password" placeholder="Password"><br>
<button onclick="login()">Login</button>
<div id="result"></div>
<script>
async function login() {
    const resp = await fetch('/vulns/auth/ajax-json/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });
    const data = await resp.json();
    document.getElementById('result').textContent = JSON.stringify(data);
    if (data.success) {
        window.location = '/vulns/auth/ajax-json/api/user';
    }
}
</script>
<p><small>Credentials: admin / password</small></p>
</body></html>`)
}

func apiUser(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_ajax")
	if err != nil || cookie.Value != "authenticated_admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error": "Not authenticated"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"user": "admin", "role": "administrator", "authenticated": true}`)
}

func session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("session_ajax")
	if err == nil && cookie.Value == "authenticated_admin" {
		fmt.Fprintf(w, `{"authenticated":true,"user":"admin"}`)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"authenticated":false}`)
}
