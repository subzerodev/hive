package csrf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/subzerodev/hive/handlers"
)

var (
	tokens   = make(map[string]bool)
	tokensMu sync.RWMutex
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth-session/csrf/vulnerable", vulnerable)
		handlers.Handle("/vulns/auth-session/csrf/fp/with-token", fpWithToken)
	})
}

func vulnerable(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		email := r.FormValue("email")
		// VULNERABLE: No CSRF token check - action performed without verification
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSRF - Action Completed</title></head>
<body>
<h1>Email Updated!</h1>
<p>Email changed to: %s</p>
<p><a href="/vulns/auth-session/csrf/vulnerable">Back</a></p>
</body></html>`, email)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: No CSRF token in form
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSRF - Vulnerable</title></head>
<body>
<h1>Change Email (Vulnerable)</h1>
<form method="POST">
    <input name="email" placeholder="New email">
    <button type="submit">Update</button>
</form>
<p><small>VULNERABLE: No CSRF protection</small></p>
</body></html>`)
}

func fpWithToken(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		token := r.FormValue("csrf_token")
		email := r.FormValue("email")

		// SAFE: Verify CSRF token
		tokensMu.RLock()
		valid := tokens[token]
		tokensMu.RUnlock()

		if !valid {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSRF - Rejected</title></head>
<body>
<h1>Request Rejected</h1>
<p>Invalid CSRF token</p>
<p><a href="/vulns/auth-session/csrf/fp/with-token">Back</a></p>
</body></html>`)
			return
		}

		// Delete used token
		tokensMu.Lock()
		delete(tokens, token)
		tokensMu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSRF - Action Completed</title></head>
<body>
<h1>Email Updated!</h1>
<p>Email changed to: %s</p>
<p><a href="/vulns/auth-session/csrf/fp/with-token">Back</a></p>
</body></html>`, email)
		return
	}

	// Generate CSRF token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	tokensMu.Lock()
	tokens[token] = true
	tokensMu.Unlock()

	w.Header().Set("Content-Type", "text/html")
	// SAFE: CSRF token included
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSRF - Protected</title></head>
<body>
<h1>Change Email (Protected)</h1>
<form method="POST">
    <input type="hidden" name="csrf_token" value="%s">
    <input name="email" placeholder="New email">
    <button type="submit">Update</button>
</form>
<p><small>SAFE: CSRF token protection enabled</small></p>
</body></html>`, token)
}
