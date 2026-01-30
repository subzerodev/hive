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
