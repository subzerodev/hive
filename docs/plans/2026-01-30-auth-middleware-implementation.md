# AUTH_TYPE Middleware Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement middleware that gates all `/vulns/*` routes behind configurable authentication based on `AUTH_TYPE` environment variable.

**Architecture:** Middleware in `auth/` package wraps the `/vulns/` handler in main.go. Each auth type has a validator function and returns real-world responses when unauthenticated. Cookie-based auth handlers get path fixes and session endpoints.

**Tech Stack:** Go net/http, no external dependencies

---

## Task 1: Create auth/validators.go

**Files:**
- Create: `auth/validators.go`

**Step 1: Create the validators file**

```go
// auth/validators.go
package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ValidateFormPost checks session_formpost cookie
func ValidateFormPost(r *http.Request) bool {
	cookie, err := r.Cookie("session_formpost")
	return err == nil && cookie.Value == "authenticated_admin"
}

// ValidateAjaxJSON checks session_ajax cookie
func ValidateAjaxJSON(r *http.Request) bool {
	cookie, err := r.Cookie("session_ajax")
	return err == nil && cookie.Value == "authenticated_admin"
}

// ValidateMultiStep checks multistep_session cookie
func ValidateMultiStep(r *http.Request) bool {
	cookie, err := r.Cookie("multistep_session")
	return err == nil && cookie.Value == "authenticated"
}

// ValidateOAuth checks oauth_session cookie
func ValidateOAuth(r *http.Request) bool {
	cookie, err := r.Cookie("oauth_session")
	return err == nil && cookie.Value == "authenticated_oauth"
}

// ValidateHTTPBasic checks Authorization header with Basic auth
func ValidateHTTPBasic(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == "admin" && pass == "password"
}

// ValidateJWT checks Authorization Bearer token
func ValidateJWT(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	return validateJWTToken(token)
}

// validateJWTToken validates a JWT token structure and expiry
func validateJWTToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Decode and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	// Only accept HS256 (match fpValidated behavior)
	if header.Alg != "HS256" {
		return false
	}

	// Decode payload and check expiry
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var payload struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	// Check expiration
	if payload.Exp > 0 && payload.Exp < time.Now().Unix() {
		return false
	}

	// Check we have a subject
	return payload.Sub != ""
}
```

**Step 2: Verify it compiles**

Run: `go build ./auth/`
Expected: No errors

**Step 3: Commit**

```bash
git add auth/validators.go
git commit -m "feat(auth): add session validators for each auth type"
```

---

## Task 2: Create auth/middleware.go

**Files:**
- Create: `auth/middleware.go`

**Step 1: Create the middleware file**

```go
// auth/middleware.go
package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// Middleware wraps a handler with authentication based on authType.
// If authType is "none" or empty, all requests pass through.
// Otherwise, requests to /vulns/* (except /vulns/auth/*) require valid session.
func Middleware(authType string, next http.Handler) http.Handler {
	// No auth - pass through everything
	if authType == "" || authType == "none" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for /vulns/auth/* endpoints (login pages, etc.)
		if strings.HasPrefix(r.URL.Path, "/vulns/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		// Validate session based on auth type
		if isAuthenticated(authType, r) {
			next.ServeHTTP(w, r)
			return
		}

		// Not authenticated - return real-world response for this auth type
		handleUnauthenticated(authType, w, r)
	})
}

// isAuthenticated dispatches to the appropriate validator
func isAuthenticated(authType string, r *http.Request) bool {
	switch authType {
	case "form-post":
		return ValidateFormPost(r)
	case "ajax-json":
		return ValidateAjaxJSON(r)
	case "multi-step":
		return ValidateMultiStep(r)
	case "oauth":
		return ValidateOAuth(r)
	case "http-basic":
		return ValidateHTTPBasic(r)
	case "jwt":
		return ValidateJWT(r)
	default:
		return false
	}
}

// handleUnauthenticated returns the appropriate response for each auth type
func handleUnauthenticated(authType string, w http.ResponseWriter, r *http.Request) {
	switch authType {
	case "form-post":
		http.Redirect(w, r, "/vulns/auth/form-post/login", http.StatusFound)

	case "ajax-json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"unauthorized","login_url":"/vulns/auth/ajax-json/login"}`)

	case "multi-step":
		http.Redirect(w, r, "/vulns/auth/multi-step/step1", http.StatusFound)

	case "oauth":
		http.Redirect(w, r, "/vulns/auth/oauth/start", http.StatusFound)

	case "http-basic":
		w.Header().Set("WWW-Authenticate", `Basic realm="HIVE Protected Area"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")

	case "jwt":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"token_required","message":"Authorization header with Bearer token required"}`)

	default:
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
	}
}
```

**Step 2: Verify it compiles**

Run: `go build ./auth/`
Expected: No errors

**Step 3: Commit**

```bash
git add auth/middleware.go
git commit -m "feat(auth): add auth middleware with real-world responses"
```

---

## Task 3: Wire middleware into main.go

**Files:**
- Modify: `main.go`

**Step 1: Add import for auth package**

Add to imports section:
```go
"github.com/subzerodev/hive/auth"
```

**Step 2: Read AUTH_TYPE and log it**

Add after `db.Init()` call:
```go
// Read auth type
authType := os.Getenv("AUTH_TYPE")
if authType == "" {
	authType = "none"
}
log.Printf("AUTH_TYPE: %s", authType)
```

**Step 3: Wrap the /vulns/ handler with middleware**

Replace the existing `/vulns/` handler registration:

From:
```go
http.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
```

To:
```go
vulnsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
```

And at the end of that handler function, change:
```go
})
```

To:
```go
})

http.Handle("/vulns/", auth.Middleware(authType, vulnsHandler))
```

**Step 4: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 5: Commit**

```bash
git add main.go
git commit -m "feat: wire auth middleware into /vulns/ routes"
```

---

## Task 4: Fix cookie paths in formpost handler

**Files:**
- Modify: `vulns/auth/formpost/handlers.go`

**Step 1: Update login cookie path**

Change line with `Path: "/vulns/auth/form-post/",` to:
```go
Path:     "/",
```

**Step 2: Update logout cookie path**

Change line with `Path: "/vulns/auth/form-post/",` in logout to:
```go
Path:    "/",
```

**Step 3: Add session endpoint**

Add to the handlers.Register block:
```go
handlers.Handle("/vulns/auth/form-post/session", session)
```

Add new function:
```go
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
```

**Step 4: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 5: Commit**

```bash
git add vulns/auth/formpost/handlers.go
git commit -m "feat(auth): fix cookie path and add session endpoint for form-post"
```

---

## Task 5: Fix cookie paths in ajaxjson handler

**Files:**
- Modify: `vulns/auth/ajaxjson/handlers.go`

**Step 1: Update login cookie path**

Change `Path: "/vulns/auth/ajax-json/",` to:
```go
Path:     "/",
```

**Step 2: Add session endpoint**

Add to handlers.Register block:
```go
handlers.Handle("/vulns/auth/ajax-json/session", session)
```

Add new function:
```go
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
```

**Step 3: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 4: Commit**

```bash
git add vulns/auth/ajaxjson/handlers.go
git commit -m "feat(auth): fix cookie path and add session endpoint for ajax-json"
```

---

## Task 6: Fix cookie paths in multistep handler

**Files:**
- Modify: `vulns/auth/multistep/handlers.go`

**Step 1: Update step1 cookie path**

Change `Path: "/vulns/auth/multi-step/",` in step1 to:
```go
Path:    "/",
```

**Step 2: Update step2 cookie path**

Change `Path: "/vulns/auth/multi-step/",` in step2 to:
```go
Path:    "/",
```

**Step 3: Add session endpoint**

Add to handlers.Register block:
```go
handlers.Handle("/vulns/auth/multi-step/session", session)
```

Add new function:
```go
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
```

**Step 4: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 5: Commit**

```bash
git add vulns/auth/multistep/handlers.go
git commit -m "feat(auth): fix cookie path and add session endpoint for multi-step"
```

---

## Task 7: Fix cookie paths in oauth handler

**Files:**
- Modify: `vulns/auth/oauth/handlers.go`

**Step 1: Update callback cookie path**

Change `Path: "/vulns/auth/oauth/",` to:
```go
Path:    "/",
```

**Step 2: Add session endpoint**

Add to handlers.Register block:
```go
handlers.Handle("/vulns/auth/oauth/session", session)
```

Add new function:
```go
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
```

**Step 3: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 4: Commit**

```bash
git add vulns/auth/oauth/handlers.go
git commit -m "feat(auth): fix cookie path and add session endpoint for oauth"
```

---

## Task 8: Add session endpoint to httpbasic handler

**Files:**
- Modify: `vulns/auth/httpbasic/handlers.go`

**Step 1: Add session endpoint**

Add to handlers.Register block:
```go
handlers.Handle("/vulns/auth/http-basic/session", session)
```

Add new function:
```go
func session(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if ok && username == "admin" && password == "password" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authenticated":true,"user":"admin"}`)
		return
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="HIVE Protected Area"`)
	w.WriteHeader(http.StatusUnauthorized)
}
```

**Step 2: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 3: Commit**

```bash
git add vulns/auth/httpbasic/handlers.go
git commit -m "feat(auth): add session endpoint for http-basic"
```

---

## Task 9: Add session endpoint to jwt handler

**Files:**
- Modify: `vulns/auth/jwt/handlers.go`

**Step 1: Add session endpoint**

Add to handlers.Register block:
```go
handlers.Handle("/vulns/auth/jwt/session", session)
```

Add new function:
```go
func session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"authenticated":false,"error":"token_required"}`)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"authenticated":false,"error":"invalid_token"}`)
		return
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"authenticated":false,"error":"invalid_token"}`)
		return
	}

	var payload struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"authenticated":false,"error":"invalid_token"}`)
		return
	}

	// Check expiration
	if payload.Exp > 0 && payload.Exp < time.Now().Unix() {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"authenticated":false,"error":"token_expired"}`)
		return
	}

	fmt.Fprintf(w, `{"authenticated":true,"user":"%s"}`, payload.Sub)
}
```

**Step 2: Verify it compiles**

Run: `go build -o /dev/null .`
Expected: No errors

**Step 3: Commit**

```bash
git add vulns/auth/jwt/handlers.go
git commit -m "feat(auth): add session endpoint for jwt"
```

---

## Task 10: Manual Integration Test

**Step 1: Build and run with AUTH_TYPE=form-post**

```bash
AUTH_TYPE=form-post go run .
```

**Step 2: Test unauthenticated access**

In another terminal:
```bash
curl -v http://localhost:8080/vulns/
```

Expected: 302 redirect to `/vulns/auth/form-post/login`

**Step 3: Test auth endpoint is accessible**

```bash
curl http://localhost:8080/vulns/auth/form-post/login
```

Expected: 200 with HTML login form

**Step 4: Test login and session**

```bash
# Login and capture cookie
curl -c cookies.txt -d "username=admin&password=password" -X POST http://localhost:8080/vulns/auth/form-post/login

# Access protected route with cookie
curl -b cookies.txt http://localhost:8080/vulns/
```

Expected: 200 with vulns index page

**Step 5: Test session endpoint**

```bash
curl -b cookies.txt http://localhost:8080/vulns/auth/form-post/session
```

Expected: `{"authenticated":true,"user":"admin"}`

**Step 6: Stop the server and clean up**

```bash
rm cookies.txt
```

---

## Task 11: Final Commit

**Step 1: Verify all tests pass**

Run: `go build -o /dev/null . && echo "Build OK"`
Expected: Build OK

**Step 2: Review changes**

Run: `git log --oneline feature/auth-middleware ^main`

Expected: See all commits from this implementation
