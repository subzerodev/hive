package hostheader

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/host-header/injection", injection)
		handlers.Handle("/vulns/config/host-header/fp/validated", fpValidated)
	})
}

func injection(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	// VULNERABLE: Host header used directly in response
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Host Header Injection</title></head>
<body>
<h1>Password Reset</h1>
<p>Reset link would be sent to:</p>
<pre>https://%s/reset?token=abc123</pre>
<p>Try: curl -H "Host: evil.com" this-url</p>
<p><small>VULNERABLE: Host header reflected in password reset URL</small></p>
</body></html>`, host)
}

func fpValidated(w http.ResponseWriter, r *http.Request) {
	// SAFE: Validate host header
	allowedHosts := map[string]bool{
		"localhost:8080": true,
		"hive.local":     true,
		"127.0.0.1:8080": true,
	}

	host := r.Host
	if !allowedHosts[strings.ToLower(host)] {
		http.Error(w, "Invalid Host", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Host Header - Validated</title></head>
<body>
<h1>Password Reset (Protected)</h1>
<p>Reset link uses validated host:</p>
<pre>https://%s/reset?token=abc123</pre>
<p><small>SAFE: Host header validated against whitelist</small></p>
</body></html>`, host)
}
