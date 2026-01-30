package ssrf

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/ssrf/http", httpSSRF)
		handlers.Handle("/vulns/ssrf/dns", dnsSSRF)
		handlers.Handle("/vulns/ssrf/fp/validated", fpValidated)
	})
}

func httpSSRF(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - HTTP</title></head>
<body>
<h1>URL Fetcher</h1>
<form method="GET">
    <input name="url" placeholder="URL to fetch" value="http://example.com" style="width:300px">
    <button type="submit">Fetch</button>
</form>
<h2>Try:</h2>
<ul>
    <li><a href="?url=http://localhost:8080/health">Internal: localhost:8080/health</a></li>
    <li><a href="?url=http://127.0.0.1:8080/health">Internal: 127.0.0.1</a></li>
    <li><a href="?url=file:///etc/passwd">File: /etc/passwd</a></li>
</ul>
<p><small>VULNERABLE: No URL validation - can access internal services</small></p>
</body></html>`)
		return
	}

	// VULNERABLE: No validation - fetches any URL including internal
	resp, err := http.Get(targetURL)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Error</h1><pre>%v</pre><a href="/vulns/ssrf/http">Back</a></body></html>`, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - Result</title></head>
<body>
<h1>Fetched: %s</h1>
<p>Status: %s</p>
<h2>Content:</h2>
<pre>%s</pre>
<a href="/vulns/ssrf/http">Back</a>
</body></html>`, targetURL, resp.Status, string(body))
}

func dnsSSRF(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - DNS</title></head>
<body>
<h1>DNS Lookup</h1>
<form method="GET">
    <input name="host" placeholder="Hostname to lookup" value="example.com" style="width:300px">
    <button type="submit">Lookup</button>
</form>
<h2>Try:</h2>
<ul>
    <li><a href="?host=localhost">localhost</a></li>
    <li><a href="?host=internal.company.local">internal.company.local</a></li>
    <li><a href="?host=169.254.169.254">AWS metadata (169.254.169.254)</a></li>
</ul>
<p><small>VULNERABLE: No hostname validation - can resolve internal DNS</small></p>
</body></html>`)
		return
	}

	// VULNERABLE: No validation - resolves any hostname
	ips, err := net.LookupIP(hostname)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>DNS Error</h1><pre>%v</pre><a href="/vulns/ssrf/dns">Back</a></body></html>`, err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - DNS Result</title></head>
<body>
<h1>DNS Lookup: %s</h1>
<h2>Resolved IPs:</h2>
<ul>`, hostname)
	for _, ip := range ips {
		fmt.Fprintf(w, `<li>%s</li>`, ip.String())
	}
	fmt.Fprintf(w, `</ul>
<a href="/vulns/ssrf/dns">Back</a>
</body></html>`)
}

func fpValidated(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - Safe</title></head>
<body>
<h1>URL Fetcher (Safe)</h1>
<form method="GET">
    <input name="url" placeholder="URL to fetch" value="http://example.com" style="width:300px">
    <button type="submit">Fetch</button>
</form>
<p><small>SAFE: Only external HTTPS URLs allowed</small></p>
</body></html>`)
		return
	}

	// SAFE: Validate URL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Block internal addresses
	blocked := []string{"localhost", "127.0.0.1", "0.0.0.0", "169.254.", "10.", "192.168.", "172."}
	host := strings.ToLower(parsed.Host)
	for _, b := range blocked {
		if strings.Contains(host, b) {
			http.Error(w, "Internal addresses not allowed", http.StatusForbidden)
			return
		}
	}

	// Only allow https
	if parsed.Scheme != "https" {
		http.Error(w, "Only HTTPS URLs allowed", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "Failed to fetch", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - Result</title></head>
<body>
<h1>Fetched (Safe): %s</h1>
<p>Status: %s</p>
<pre>%s</pre>
<a href="/vulns/ssrf/fp/validated">Back</a>
</body></html>`, targetURL, resp.Status, string(body))
}
