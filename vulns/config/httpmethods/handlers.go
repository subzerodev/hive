package httpmethods

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/http-methods/trace", trace)
		handlers.Handle("/vulns/config/http-methods/put", put)
		handlers.Handle("/vulns/config/http-methods/fp/restricted", fpRestricted)
	})
}

func trace(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: TRACE method enabled
	if r.Method == http.MethodTrace || r.Method == "TRACE" {
		w.Header().Set("Content-Type", "message/http")
		fmt.Fprintf(w, "TRACE / HTTP/1.1\r\n")
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Fprintf(w, "%s: %s\r\n", name, value)
			}
		}
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP Methods - TRACE</title></head>
<body>
<h1>TRACE Method Enabled</h1>
<p>Send a TRACE request to see reflected headers:</p>
<pre>curl -X TRACE %s</pre>
<p><small>VULNERABLE: TRACE method can expose cookies via XST</small></p>
</body></html>`, r.URL.Path)
}

func put(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: PUT method enabled
	if r.Method == http.MethodPut {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "PUT request accepted. File would be created/modified.")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP Methods - PUT</title></head>
<body>
<h1>PUT Method Enabled</h1>
<p>Send a PUT request to upload/modify files:</p>
<pre>curl -X PUT -d "content" %s</pre>
<p><small>VULNERABLE: PUT method may allow unauthorized file modification</small></p>
</body></html>`, r.URL.Path)
}

func fpRestricted(w http.ResponseWriter, r *http.Request) {
	// SAFE: Only allow GET and POST
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP Methods - Restricted</title></head>
<body>
<h1>Restricted HTTP Methods</h1>
<p>Only GET and POST are allowed.</p>
<p>TRACE and PUT will receive 405 Method Not Allowed.</p>
<p><small>SAFE: Dangerous methods disabled</small></p>
</body></html>`)
}
