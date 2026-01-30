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
