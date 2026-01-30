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
		// JWT vulnerability test cases
		handlers.Handle("/vulns/auth/jwt/none-alg", noneAlg)
		handlers.Handle("/vulns/auth/jwt/weak-secret", weakSecret)
		handlers.Handle("/vulns/auth/jwt/no-expiry", noExpiry)
		handlers.Handle("/vulns/auth/jwt/url-param", urlParam)
		handlers.Handle("/vulns/auth/jwt/fp/validated", fpValidated)
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

// noneAlg - VULNERABLE: Accepts tokens with "none" algorithm
func noneAlg(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	w.Header().Set("Content-Type", "text/html")

	if token == "" {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","admin":true}`))
		token = header + "." + payload + "."
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT - None Algorithm</title></head>
<body>
<h1>JWT Vulnerability - None Algorithm</h1>
<form method="GET">
    <textarea name="token" rows="3" cols="60">%s</textarea><br>
    <button type="submit">Verify Token</button>
</form>
<h2>Token Validation:</h2>
<pre id="output">`, token)

	parts := strings.Split(token, ".")
	if len(parts) >= 2 {
		headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])

		var header struct {
			Alg string `json:"alg"`
		}
		json.Unmarshal(headerBytes, &header)

		var payload struct {
			Sub   string `json:"sub"`
			Admin bool   `json:"admin"`
		}
		json.Unmarshal(payloadBytes, &payload)

		// VULNERABLE: Accepts "none" algorithm
		if strings.ToLower(header.Alg) == "none" {
			fmt.Fprintf(w, "Token accepted (none algorithm)!\nUser: %s\nAdmin: %v", payload.Sub, payload.Admin)
		} else {
			fmt.Fprintf(w, "Token requires signature verification")
		}
	} else {
		fmt.Fprintf(w, "Invalid token format")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Create a token with alg:"none" and empty signature</small></p>
<p><a href="/vulns/auth/jwt/">Back to JWT Tests</a></p>
</body></html>`)
}

// weakSecret - VULNERABLE: Uses weak secret "secret"
func weakSecret(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	w.Header().Set("Content-Type", "text/html")

	if token == "" {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user","admin":false}`))
		token = header + "." + payload + ".fake_sig_weak_secret"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT - Weak Secret</title></head>
<body>
<h1>JWT Vulnerability - Weak Secret Key</h1>
<p>Secret key: <code>secret</code> (easily brute-forced)</p>
<form method="GET">
    <textarea name="token" rows="3" cols="60">%s</textarea><br>
    <button type="submit">Verify Token</button>
</form>
<h2>Token Validation:</h2>
<pre id="output">`, token)

	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var payload struct {
			Sub   string `json:"sub"`
			Admin bool   `json:"admin"`
		}
		json.Unmarshal(payloadBytes, &payload)
		fmt.Fprintf(w, "Token parsed\nUser: %s\nAdmin: %v\n\nSecret is 'secret' - brute-force it!", payload.Sub, payload.Admin)
	} else {
		fmt.Fprintf(w, "Invalid token format")
	}

	fmt.Fprintf(w, `</pre>
<h3>Hint:</h3>
<p><small>Brute-force common secrets: secret, password, 123456</small></p>
<p><a href="/vulns/auth/jwt/">Back to JWT Tests</a></p>
</body></html>`)
}

// noExpiry - VULNERABLE: Does not check token expiration
func noExpiry(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	w.Header().Set("Content-Type", "text/html")

	if token == "" {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","admin":true,"exp":0}`))
		token = header + "." + payload + "."
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT - No Expiry Check</title></head>
<body>
<h1>JWT Vulnerability - Expired Tokens Accepted</h1>
<form method="GET">
    <textarea name="token" rows="3" cols="60">%s</textarea><br>
    <button type="submit">Verify Token</button>
</form>
<h2>Token Validation:</h2>
<pre id="output">`, token)

	parts := strings.Split(token, ".")
	if len(parts) >= 2 {
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var payload struct {
			Sub   string `json:"sub"`
			Admin bool   `json:"admin"`
			Exp   int64  `json:"exp"`
		}
		json.Unmarshal(payloadBytes, &payload)
		// VULNERABLE: Does not check expiration
		fmt.Fprintf(w, "Token accepted!\nUser: %s\nAdmin: %v\nExp: %d (not checked!)", payload.Sub, payload.Admin, payload.Exp)
	} else {
		fmt.Fprintf(w, "Invalid token format")
	}

	fmt.Fprintf(w, `</pre>
<h3>Vulnerability:</h3>
<p><small>Expired tokens still accepted - no exp claim validation</small></p>
<p><a href="/vulns/auth/jwt/">Back to JWT Tests</a></p>
</body></html>`)
}

// urlParam - VULNERABLE: JWT in URL parameter (leaks via referrer, logs)
func urlParam(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("jwt")

	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT - URL Parameter</title></head>
<body>
<h1>JWT Vulnerability - Token in URL</h1>
<p>JWT in URL leaks via referrer header, browser history, server logs</p>
<form method="GET">
    <input name="jwt" value="%s" placeholder="JWT token" style="width:400px">
    <button type="submit">Access</button>
</form>
<h2>Result:</h2>
<pre id="output">`, token)

	if token != "" {
		parts := strings.Split(token, ".")
		if len(parts) >= 2 {
			payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var payload struct {
				Sub   string `json:"sub"`
				Admin bool   `json:"admin"`
			}
			json.Unmarshal(payloadBytes, &payload)
			fmt.Fprintf(w, "Access granted!\nUser: %s\nAdmin: %v\n\nWARNING: Token visible in URL!", payload.Sub, payload.Admin)
		}
	} else {
		fmt.Fprintf(w, "Submit a JWT in the URL parameter")
	}

	fmt.Fprintf(w, `</pre>
<h3>Vulnerability:</h3>
<p><small>JWTs in URLs leak via Referer header, browser history, server logs</small></p>
<p><a href="/vulns/auth/jwt/">Back to JWT Tests</a></p>
</body></html>`)
}

// fpValidated - SAFE: Proper JWT validation
func fpValidated(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT - Safe</title></head>
<body>
<h1>JWT - Safe (Properly Validated)</h1>
<form method="GET">
    <textarea name="token" rows="3" cols="60">%s</textarea><br>
    <button type="submit">Verify Token</button>
</form>
<h2>Token Validation:</h2>
<pre id="output">`, token)

	if token != "" {
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
			var header struct {
				Alg string `json:"alg"`
			}
			json.Unmarshal(headerBytes, &header)

			// SAFE: Only accept HS256
			if header.Alg != "HS256" {
				fmt.Fprintf(w, "Error: Only HS256 algorithm accepted (got %s)", header.Alg)
			} else {
				payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
				var payload struct {
					Sub   string `json:"sub"`
					Admin bool   `json:"admin"`
					Exp   int64  `json:"exp"`
				}
				json.Unmarshal(payloadBytes, &payload)

				// Check expiration
				if payload.Exp > 0 && payload.Exp < time.Now().Unix() {
					fmt.Fprintf(w, "Error: Token expired")
				} else {
					fmt.Fprintf(w, "Token format valid (signature check would occur)\nUser: %s\nAdmin: %v", payload.Sub, payload.Admin)
				}
			}
		} else {
			fmt.Fprintf(w, "Invalid token format")
		}
	} else {
		fmt.Fprintf(w, "Submit a token to verify")
	}

	fmt.Fprintf(w, `</pre>
<h3>Security:</h3>
<p><small>SAFE: Algorithm whitelist, expiration check, signature verification</small></p>
<p><a href="/vulns/auth/jwt/">Back to JWT Tests</a></p>
</body></html>`)
}
