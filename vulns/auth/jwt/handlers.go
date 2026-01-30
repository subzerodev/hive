package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth/jwt/login", login)
		handlers.Handle("/vulns/auth/jwt/protected", protected)
	})
}

func createToken(username string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%s","exp":%d}`, username, time.Now().Add(24*time.Hour).Unix())))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake_signature"))
	return header + "." + payload + "." + signature
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
			token := createToken(creds.Username)
			fmt.Fprintf(w, `{"token": "%s"}`, token)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error": "Invalid credentials"}`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT Login</title></head>
<body>
<h1>JWT Login</h1>
<input id="username" placeholder="Username"><br>
<input type="password" id="password" placeholder="Password"><br>
<button onclick="login()">Login</button>
<div id="token"></div>
<div id="result"></div>
<script>
async function login() {
    const resp = await fetch('/vulns/auth/jwt/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });
    const data = await resp.json();
    if (data.token) {
        document.getElementById('token').textContent = 'Token: ' + data.token;
        localStorage.setItem('jwt_token', data.token);
        testProtected(data.token);
    } else {
        document.getElementById('token').textContent = 'Error: ' + data.error;
    }
}
async function testProtected(token) {
    const resp = await fetch('/vulns/auth/jwt/protected', {
        headers: {'Authorization': 'Bearer ' + token}
    });
    const text = await resp.text();
    document.getElementById('result').innerHTML = '<h3>Protected endpoint response:</h3>' + text;
}
</script>
<p><small>Credentials: admin / password</small></p>
</body></html>`)
}

func protected(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error": "Missing or invalid Authorization header"}`)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error": "Invalid token format"}`)
		return
	}

	// Decode payload (simplified - not validating signature for testbed)
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	json.Unmarshal(payloadBytes, &payload)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Welcome to protected area", "user": "%s"}`, payload.Sub)
}
