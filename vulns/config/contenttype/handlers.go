package contenttype

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/content-type/missing", missing)
		handlers.Handle("/vulns/config/content-type/sniffing", sniffing)
		handlers.Handle("/vulns/config/content-type/fp/nosniff", fpNosniff)
	})
}

func missing(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No Content-Type header
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Content-Type Missing</title></head>
<body>
<h1>No Content-Type Header</h1>
<p>This response has no Content-Type header set.</p>
<p>Browser may MIME-sniff and interpret content incorrectly.</p>
<p><small>VULNERABLE: Missing Content-Type header</small></p>
</body></html>`)
}

func sniffing(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Content-Type set but no X-Content-Type-Options
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `<script>alert('XSS via MIME sniffing')</script>
This is supposed to be plain text but lacks X-Content-Type-Options: nosniff
Browser may interpret as HTML and execute script.`)
}

func fpNosniff(w http.ResponseWriter, r *http.Request) {
	// SAFE: Content-Type with X-Content-Type-Options: nosniff
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprintf(w, `<script>alert('safe')</script>
This content has X-Content-Type-Options: nosniff
Browser will NOT sniff and will respect text/plain`)
}
