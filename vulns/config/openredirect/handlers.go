package openredirect

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/open-redirect/basic", basic)
		handlers.Handle("/vulns/config/open-redirect/fp/validated", fpValidated)
	})
}

func basic(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("url")
	if redirectURL == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Vulnerable</title></head>
<body>
<h1>Redirect Service</h1>
<form method="GET">
    <input name="url" placeholder="URL to redirect" value="https://example.com">
    <button type="submit">Redirect</button>
</form>
<p>Examples:</p>
<ul>
    <li><a href="?url=https://evil.com">Redirect to evil.com</a></li>
    <li><a href="?url=//evil.com">Protocol-relative redirect</a></li>
</ul>
<p><small>VULNERABLE: No URL validation</small></p>
</body></html>`)
		return
	}

	// VULNERABLE: Unvalidated redirect
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func fpValidated(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("url")
	if redirectURL == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Open Redirect - Protected</title></head>
<body>
<h1>Redirect Service (Protected)</h1>
<form method="GET">
    <input name="url" placeholder="URL to redirect" value="/dashboard">
    <button type="submit">Redirect</button>
</form>
<p><small>SAFE: Only relative URLs or whitelisted domains allowed</small></p>
</body></html>`)
		return
	}

	// SAFE: Validate redirect URL
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Only allow relative URLs or specific domains
	allowedDomains := map[string]bool{
		"":               true, // Relative URL
		"hive.local":     true,
		"app.hive.local": true,
	}

	if !allowedDomains[strings.ToLower(parsed.Host)] {
		http.Error(w, "Redirect to external domain not allowed", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
