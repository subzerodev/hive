package pathtraversal

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/file/pathtraversal/get", getTraversal)
		handlers.Handle("/vulns/file/pathtraversal/post", postTraversal)
		handlers.Handle("/vulns/file/pathtraversal/fp/sanitized", fpSanitized)
	})
}

func getTraversal(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		filename = "readme.txt"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Path Traversal - GET</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Viewer</h1>
<form method="GET">
    <input name="file" value="%s" placeholder="Filename">
    <button type="submit">Read File</button>
</form>
<h2>File Contents:</h2>
<pre>`, filename)

	// VULNERABLE: Direct path traversal
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
	} else {
		fmt.Fprintf(w, "%s", content)
	}

	fmt.Fprintf(w, `</pre>
<p><small>Try: ../../../etc/passwd</small></p>
</div>
</body></html>`)
}

func postTraversal(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Path Traversal - POST</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Viewer (POST)</h1>
<form method="POST">
    <input name="file" value="readme.txt" placeholder="Filename">
    <button type="submit">Read File</button>
</form>
<p><small>Try: ../../../etc/passwd</small></p>
</div>
</body></html>`)
		return
	}

	r.ParseForm()
	filename := r.FormValue("file")
	if filename == "" {
		filename = "readme.txt"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Path Traversal - POST</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Viewer (POST)</h1>
<form method="POST">
    <input name="file" value="%s" placeholder="Filename">
    <button type="submit">Read File</button>
</form>
<h2>File Contents:</h2>
<pre>`, filename)

	// VULNERABLE: Direct path traversal via POST
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
	} else {
		fmt.Fprintf(w, "%s", content)
	}

	fmt.Fprintf(w, `</pre>
</div>
</body></html>`)
}

func fpSanitized(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		filename = "readme.txt"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Path Traversal - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Viewer (Safe)</h1>
<form method="GET">
    <input name="file" value="%s" placeholder="Filename">
    <button type="submit">Read File</button>
</form>
<h2>File Contents:</h2>
<pre>`, filename)

	// SAFE: Sanitize path - remove traversal attempts and restrict to safe directory
	basePath := "./static/test"
	cleanName := filepath.Base(filename) // Strip directory components
	cleanName = strings.ReplaceAll(cleanName, "..", "")
	safePath := filepath.Join(basePath, cleanName)

	content, err := os.ReadFile(safePath)
	if err != nil {
		fmt.Fprintf(w, "Error: File not found or access denied")
	} else {
		fmt.Fprintf(w, "%s", content)
	}

	fmt.Fprintf(w, `</pre>
<p><small>Path traversal is blocked - only files in safe directory allowed</small></p>
</div>
</body></html>`)
}
