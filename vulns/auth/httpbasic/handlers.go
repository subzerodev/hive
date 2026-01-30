package httpbasic

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/auth/http-basic/protected", protected)
		handlers.Handle("/vulns/auth/http-basic/session", session)
	})
}

func protected(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()

	if !ok || username != "admin" || password != "password" {
		w.Header().Set("WWW-Authenticate", `Basic realm="HIVE Protected Area"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP Basic Protected</title></head>
<body>
<h1>Protected Area (HTTP Basic)</h1>
<p>Successfully authenticated via HTTP Basic auth.</p>
<p>Welcome, %s!</p>
</body></html>`, username)
}

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
