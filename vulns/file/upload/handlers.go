package upload

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/file/upload/unrestricted", unrestricted)
		handlers.Handle("/vulns/file/upload/fp/validated", fpValidated)
	})
	// Create uploads directory
	os.MkdirAll("./uploads", 0755)
}

func unrestricted(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>File Upload - Unrestricted</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Upload (Unrestricted)</h1>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
<p><small>VULNERABLE: Any file type accepted</small></p>
</div>
</body></html>`)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// VULNERABLE: No validation of file type or content
	destPath := filepath.Join("./uploads", header.Filename)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	io.Copy(dest, file)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>File Upload - Success</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Uploaded</h1>
<p>File saved as: %s</p>
<p><a href="/vulns/file/upload/unrestricted">Upload another</a></p>
</div>
</body></html>`, header.Filename)
}

func fpValidated(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>File Upload - Validated</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Upload (Validated)</h1>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" accept=".txt,.pdf,.png,.jpg">
    <button type="submit">Upload</button>
</form>
<p><small>SAFE: Only specific file types allowed (.txt, .pdf, .png, .jpg)</small></p>
</div>
</body></html>`)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// SAFE: Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowedExts := map[string]bool{".txt": true, ".pdf": true, ".png": true, ".jpg": true}

	if !allowedExts[ext] {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>File Upload - Rejected</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Upload Rejected</h1>
<p>File type not allowed. Only .txt, .pdf, .png, .jpg files accepted.</p>
<p><a href="/vulns/file/upload/fp/validated">Try again</a></p>
</div>
</body></html>`)
		return
	}

	// Generate safe filename
	safeFilename := filepath.Base(header.Filename)
	safeFilename = strings.ReplaceAll(safeFilename, "..", "")
	destPath := filepath.Join("./uploads", safeFilename)

	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	io.Copy(dest, file)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>File Upload - Success</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>File Uploaded</h1>
<p>File saved as: %s</p>
<p><a href="/vulns/file/upload/fp/validated">Upload another</a></p>
</div>
</body></html>`, safeFilename)
}
