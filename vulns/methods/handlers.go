// vulns/methods/handlers.go
package methods

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// HTTP PUT enabled
		handlers.Handle("/vulns/methods/put", putMethod)
		// HTTP TRACE enabled
		handlers.Handle("/vulns/methods/trace", traceMethod)
		// HTTP DELETE enabled
		handlers.Handle("/vulns/methods/delete", deleteMethod)
		// HTTP OPTIONS (CORS preflight)
		handlers.Handle("/vulns/methods/options", optionsMethod)
		// Arbitrary methods
		handlers.Handle("/vulns/methods/arbitrary", arbitraryMethod)
		// False positive
		handlers.Handle("/vulns/methods/fp/restricted", fpRestricted)
	})
}

func putMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PUT Method - Success</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>PUT Method Accepted</h1>
<p>File upload via PUT method was accepted.</p>
<pre>
Method: PUT
Content-Length: %d
Content-Type: %s
</pre>
<p><strong>Vulnerability:</strong> PUT method can be used to upload files to the server.</p>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`, r.ContentLength, r.Header.Get("Content-Type"))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP PUT Method</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP PUT Method Enabled</h1>
<p>This endpoint accepts PUT requests for file uploads.</p>
<h2>Test with curl:</h2>
<pre>curl -X PUT -d "malicious content" %s</pre>
<h2>Allowed Methods:</h2>
<pre>GET, POST, PUT, DELETE, OPTIONS</pre>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`, r.URL.Path)
}

func traceMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method == "TRACE" {
		w.Header().Set("Content-Type", "message/http")
		fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\n", r.URL.Path)
		fmt.Fprintf(w, "Host: %s\r\n", r.Host)
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Fprintf(w, "%s: %s\r\n", name, value)
			}
		}
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Allow", "GET, POST, TRACE, OPTIONS")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP TRACE Method</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP TRACE Method Enabled</h1>
<p>This endpoint accepts TRACE requests (Cross-Site Tracing vulnerability).</p>
<h2>Test with curl:</h2>
<pre>curl -X TRACE %s</pre>
<h2>Vulnerability:</h2>
<p>TRACE can be used for Cross-Site Tracing (XST) attacks to steal cookies marked as HttpOnly.</p>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`, r.URL.Path)
}

func deleteMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>DELETE Method - Success</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>DELETE Method Accepted</h1>
<p>Resource deletion request was accepted.</p>
<pre>
Method: DELETE
Path: %s
</pre>
<p><strong>Vulnerability:</strong> DELETE method can be used to remove resources.</p>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`, r.URL.Path)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP DELETE Method</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP DELETE Method Enabled</h1>
<p>This endpoint accepts DELETE requests.</p>
<h2>Test with curl:</h2>
<pre>curl -X DELETE %s</pre>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`, r.URL.Path)
}

func optionsMethod(w http.ResponseWriter, r *http.Request) {
	// Overly permissive CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Allow", "GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP OPTIONS - Permissive</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Overly Permissive OPTIONS Response</h1>
<h2>Response Headers:</h2>
<pre>
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE
Access-Control-Allow-Headers: *
Access-Control-Allow-Credentials: true
</pre>
<p><strong>Vulnerability:</strong> Allows any origin with credentials - security risk!</p>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`)
}

func arbitraryMethod(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Arbitrary HTTP Method</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Arbitrary HTTP Method Accepted</h1>
<p>This endpoint accepted your HTTP method.</p>
<h2>Request Details:</h2>
<pre>
Method: %s
Path: %s
</pre>
<h2>Vulnerability:</h2>
<p>Server accepts arbitrary HTTP methods which may bypass security controls.</p>
<h2>Test with curl:</h2>
<pre>curl -X FOOBAR %s</pre>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`, r.Method, r.URL.Path, r.URL.Path)
}

func fpRestricted(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, POST")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>405 Method Not Allowed</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>405 Method Not Allowed</h1>
<p>Only GET and POST methods are allowed.</p>
<h3>Security:</h3>
<p><small>SAFE: Dangerous HTTP methods are restricted</small></p>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTTP Methods - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>HTTP Methods - Safe (Restricted)</h1>
<p>Only GET and POST methods are allowed.</p>
<h3>Security:</h3>
<p><small>SAFE: PUT, DELETE, TRACE, and other dangerous methods are blocked</small></p>
<p><a href="/vulns/methods/">Back to Methods Tests</a></p>
</div>
</body></html>`)
}
