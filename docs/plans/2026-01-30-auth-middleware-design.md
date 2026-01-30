# AUTH_TYPE Middleware Design

## Overview

Add middleware that gates all `/vulns/*` routes behind configurable authentication, controlled by the `AUTH_TYPE` environment variable. Each auth type uses its native session mechanism and returns real-world responses.

## Configuration

Environment variable only:

| AUTH_TYPE | Description |
|-----------|-------------|
| `none` | No auth, everything open (default) |
| `form-post` | Traditional form login, cookie session |
| `ajax-json` | SPA-style API login, cookie session |
| `multi-step` | Username page then password page, cookie session |
| `oauth` | OAuth authorization code flow, cookie session |
| `http-basic` | Browser auth dialog, stateless per-request |
| `jwt` | Bearer token in Authorization header, stateless |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        main.go                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Auth Middleware                       │  │
│  │  - Reads AUTH_TYPE env var at startup             │  │
│  │  - Skips /vulns/auth/* routes                     │  │
│  │  - Delegates to auth-type-specific validator      │  │
│  │  - Returns real-world response on failure         │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │           Existing /vulns/* handlers              │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  auth/validators.go                     │
│  - ValidateFormPost(r) bool                            │
│  - ValidateAjaxJSON(r) bool                            │
│  - ValidateHTTPBasic(r) bool                           │
│  - ValidateJWT(r) bool                                 │
│  - etc.                                                │
└─────────────────────────────────────────────────────────┘
```

## Protected Routes

- **Protected:** All `/vulns/*` routes
- **Excluded:** `/vulns/auth/*` (login pages, login endpoints, logout, session checks)
- **Excluded:** `/health`, `/api/reset`, `/static/*`

## Middleware Implementation

### auth/middleware.go

```go
func Middleware(authType string, next http.Handler) http.Handler {
    if authType == "none" || authType == "" {
        return next
    }

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Skip auth endpoints
        if strings.HasPrefix(r.URL.Path, "/vulns/auth/") {
            next.ServeHTTP(w, r)
            return
        }

        // Validate session
        if isAuthenticated(authType, r) {
            next.ServeHTTP(w, r)
            return
        }

        // Return real-world unauthenticated response
        handleUnauthenticated(authType, w, r)
    })
}
```

## Validators

### auth/validators.go

Each validator checks the session mechanism used by its auth type:

```go
func ValidateFormPost(r *http.Request) bool {
    cookie, err := r.Cookie("session_formpost")
    return err == nil && cookie.Value == "authenticated_admin"
}

func ValidateAjaxJSON(r *http.Request) bool {
    cookie, err := r.Cookie("session_ajax")
    return err == nil && cookie.Value == "authenticated_admin"
}

func ValidateMultiStep(r *http.Request) bool {
    cookie, err := r.Cookie("multistep_session")
    return err == nil && cookie.Value == "authenticated"
}

func ValidateOAuth(r *http.Request) bool {
    cookie, err := r.Cookie("oauth_session")
    return err == nil && cookie.Value == "authenticated_oauth"
}

func ValidateHTTPBasic(r *http.Request) bool {
    user, pass, ok := r.BasicAuth()
    return ok && user == "admin" && pass == "password"
}

func ValidateJWT(r *http.Request) bool {
    auth := r.Header.Get("Authorization")
    if !strings.HasPrefix(auth, "Bearer ") {
        return false
    }
    token := strings.TrimPrefix(auth, "Bearer ")
    return validateJWTToken(token)
}
```

## Unauthenticated Responses

Each auth type returns a real-world response when not authenticated:

| Auth Type | Response |
|-----------|----------|
| `form-post` | 302 redirect to `/vulns/auth/form-post/login` |
| `ajax-json` | 401 JSON `{"error":"unauthorized","login_url":"/vulns/auth/ajax-json/login"}` |
| `multi-step` | 302 redirect to `/vulns/auth/multi-step/step1` |
| `oauth` | 302 redirect to `/vulns/auth/oauth/start` |
| `http-basic` | 401 with `WWW-Authenticate: Basic realm="HIVE Protected Area"` |
| `jwt` | 401 JSON `{"error":"token_required","message":"Authorization header with Bearer token required"}` |

## Session Check Endpoints

Each auth type has its own session endpoint for scanner polling:

- `/vulns/auth/form-post/session`
- `/vulns/auth/ajax-json/session`
- `/vulns/auth/multi-step/session`
- `/vulns/auth/oauth/session`
- `/vulns/auth/http-basic/session`
- `/vulns/auth/jwt/session`

Each returns realistic responses for that auth type:
- Cookie-based: JSON `{"authenticated":true,"user":"admin"}` or 401 `{"authenticated":false}`
- HTTP Basic: 401 with WWW-Authenticate header if no creds, 200 with user info if valid
- JWT: 401 if no/invalid token, 200 with claims if valid

## Cookie Path Fix

Existing auth handlers set cookies with narrow paths (e.g., `/vulns/auth/form-post/`). These must be changed to `/` so the middleware can see them on all `/vulns/*` routes.

**Files to update:**
- `vulns/auth/formpost/handlers.go` - login and logout cookie paths
- `vulns/auth/ajaxjson/handlers.go`
- `vulns/auth/multistep/handlers.go`
- `vulns/auth/oauth/handlers.go`

## main.go Integration

```go
import "github.com/subzerodev/hive/auth"

func main() {
    authType := os.Getenv("AUTH_TYPE")
    if authType == "" {
        authType = "none"
    }
    log.Printf("AUTH_TYPE: %s", authType)

    // ... existing setup ...

    vulnsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // existing /vulns/ handler logic
    })

    http.Handle("/vulns/", auth.Middleware(authType, vulnsHandler))
}
```

## Files Changed

**New files:**
- `auth/middleware.go`
- `auth/validators.go`

**Modified files:**
- `main.go` - Read AUTH_TYPE, wrap handler
- `vulns/auth/formpost/handlers.go` - Add /session, fix cookie path
- `vulns/auth/ajaxjson/handlers.go` - Add /session, fix cookie path
- `vulns/auth/multistep/handlers.go` - Add /session, fix cookie path
- `vulns/auth/oauth/handlers.go` - Add /session, fix cookie path
- `vulns/auth/httpbasic/handlers.go` - Add /session
- `vulns/auth/jwt/handlers.go` - Add /session

## Testing

1. Set `AUTH_TYPE=form-post` in docker-compose.yml
2. `docker-compose up --build`
3. Visit `http://localhost:8080/vulns/` - should redirect to login
4. Login with admin/password
5. Visit `http://localhost:8080/vulns/injection/sqli/mysql/error-based` - should work
6. Check `/vulns/auth/form-post/session` returns authenticated status
