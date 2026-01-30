package cors

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/cors/permissive", permissive)
		handlers.Handle("/vulns/config/cors/reflect-origin", reflectOrigin)
		handlers.Handle("/vulns/config/cors/fp/restricted", fpRestricted)
	})
}

func permissive(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Allow all origins
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")

	fmt.Fprintf(w, `{"user": "admin", "token": "secret123", "cors": "Allow-Origin: *"}`)
}

func reflectOrigin(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Reflect any origin
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "null"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")

	fmt.Fprintf(w, `{"user": "admin", "token": "secret456", "cors": "Reflected: %s"}`, origin)
}

func fpRestricted(w http.ResponseWriter, r *http.Request) {
	// SAFE: Only allow specific origins
	origin := r.Header.Get("Origin")
	allowed := map[string]bool{
		"https://trusted.example.com": true,
		"https://app.example.com":     true,
	}

	if allowed[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Content-Type", "application/json")

	fmt.Fprintf(w, `{"user": "admin", "token": "safe789", "cors": "Restricted whitelist"}`)
}
