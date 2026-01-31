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

		// Out-of-band resource load
		handlers.Handle("/vulns/ssrf/oob-http", oobHTTP)
		handlers.Handle("/vulns/ssrf/oob-dns", oobDNS)
		handlers.Handle("/vulns/ssrf/oob-image", oobImage)
	})
}

func httpSSRF(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - HTTP</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
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
</div>
</body></html>`)
		return
	}

	// VULNERABLE: No validation - fetches any URL including internal
	resp, err := http.Get(targetURL)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="/static/css/hive.css"></head><body><div class="container"><h1>Error</h1><pre>%v</pre><a href="/vulns/ssrf/http">Back</a></div></body></html>`, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - Result</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Fetched: %s</h1>
<p>Status: %s</p>
<h2>Content:</h2>
<pre>%s</pre>
<a href="/vulns/ssrf/http">Back</a>
</div>
</body></html>`, targetURL, resp.Status, string(body))
}

func dnsSSRF(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - DNS</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
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
</div>
</body></html>`)
		return
	}

	// VULNERABLE: No validation - resolves any hostname
	ips, err := net.LookupIP(hostname)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="/static/css/hive.css"></head><body><div class="container"><h1>DNS Error</h1><pre>%v</pre><a href="/vulns/ssrf/dns">Back</a></div></body></html>`, err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - DNS Result</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>DNS Lookup: %s</h1>
<h2>Resolved IPs:</h2>
<ul>`, hostname)
	for _, ip := range ips {
		fmt.Fprintf(w, `<li>%s</li>`, ip.String())
	}
	fmt.Fprintf(w, `</ul>
<a href="/vulns/ssrf/dns">Back</a>
</div>
</body></html>`)
}

func fpValidated(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSRF - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>URL Fetcher (Safe)</h1>
<form method="GET">
    <input name="url" placeholder="URL to fetch" value="http://example.com" style="width:300px">
    <button type="submit">Fetch</button>
</form>
<p><small>SAFE: Only external HTTPS URLs allowed</small></p>
</div>
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
<head><title>SSRF - Result</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Fetched (Safe): %s</h1>
<p>Status: %s</p>
<pre>%s</pre>
<a href="/vulns/ssrf/fp/validated">Back</a>
</div>
</body></html>`, targetURL, resp.Status, string(body))
}

// Out-of-band resource load - HTTP
func oobHTTP(w http.ResponseWriter, r *http.Request) {
	callback := r.URL.Query().Get("callback")
	if callback == "" {
		callback = "http://attacker.com/collect"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Out-of-Band HTTP Load</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Out-of-Band Resource Load (HTTP)</h1>
<p>Server makes HTTP request to user-controlled URL.</p>

<form method="GET">
    <label>Callback URL:</label><br>
    <input name="callback" value="%s" style="width:400px"><br><br>
    <button type="submit">Trigger Request</button>
</form>

<h2>Server Action:</h2>
<pre>// Server-side code
response := http.Get(userCallback)
log.Printf("Webhook response: %%s", response.Status)</pre>

<h2>Detection:</h2>
<p>Use Burp Collaborator or similar to detect out-of-band HTTP interaction:</p>
<pre>?callback=http://YOUR-COLLABORATOR-ID.burpcollaborator.net/</pre>

<h3>Vulnerability:</h3>
<p><small>Server performs HTTP request to attacker-controlled URL</small></p>
<p><a href="/vulns/ssrf/">Back to SSRF</a></p>
</div>
</body></html>`, callback)

	// Simulate the out-of-band HTTP request (in real app this would be background)
	go func() {
		if strings.HasPrefix(callback, "http") {
			http.Get(callback) // Fire and forget
		}
	}()
}

// Out-of-band resource load - DNS
func oobDNS(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "test.attacker.com"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Out-of-Band DNS Load</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Out-of-Band Resource Load (DNS)</h1>
<p>Server performs DNS lookup on user-controlled domain.</p>

<form method="GET">
    <label>Domain to lookup:</label><br>
    <input name="domain" value="%s" style="width:400px"><br><br>
    <button type="submit">Trigger Lookup</button>
</form>

<h2>Server Action:</h2>
<pre>// Server-side code
ips, _ := net.LookupIP(userDomain)
// Processing continues...</pre>

<h2>Detection:</h2>
<p>Use Burp Collaborator for DNS-only detection:</p>
<pre>?domain=YOUR-COLLABORATOR-ID.burpcollaborator.net</pre>

<h3>Vulnerability:</h3>
<p><small>Server performs DNS lookup to attacker-controlled domain</small></p>
<p><a href="/vulns/ssrf/">Back to SSRF</a></p>
</div>
</body></html>`, domain)

	// Simulate the out-of-band DNS lookup
	go func() {
		net.LookupIP(domain)
	}()
}

// Out-of-band via image/resource loading
func oobImage(w http.ResponseWriter, r *http.Request) {
	imgURL := r.URL.Query().Get("img")
	if imgURL == "" {
		imgURL = "http://attacker.com/image.png"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Out-of-Band Image Load</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Out-of-Band Resource Load (Image)</h1>
<p>Page loads image from user-controlled URL.</p>

<form method="GET">
    <label>Image URL:</label><br>
    <input name="img" value="%s" style="width:400px"><br><br>
    <button type="submit">Load Image</button>
</form>

<h2>Loaded Image:</h2>
<img src="%s" onerror="this.alt='Failed to load'" style="max-width:300px; border:1px solid #ccc;">

<h2>Server-Side Fetch (if applicable):</h2>
<pre>// Some apps fetch images server-side for processing
imageData := http.Get(userImageURL)
processImage(imageData)</pre>

<h3>Vulnerability:</h3>
<p><small>External resource loaded from user-controlled URL</small></p>
<p><a href="/vulns/ssrf/">Back to SSRF</a></p>
</div>
</body></html>`, imgURL, imgURL)
}
