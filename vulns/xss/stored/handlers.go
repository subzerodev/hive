package stored

import (
	"fmt"
	"html"
	"net/http"
	"sync"

	"github.com/subzerodev/hive/handlers"
)

var (
	comments     []string
	commentsMu   sync.RWMutex
	safeComments []string
	safeMu       sync.RWMutex
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/xss/stored/comment", comment)
		handlers.Handle("/vulns/xss/stored/fp/escaped", fpEscaped)
	})
}

func comment(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		text := r.FormValue("comment")
		if text != "" {
			commentsMu.Lock()
			comments = append(comments, text)
			commentsMu.Unlock()
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Stored XSS - Comments</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Comments</h1>
<form method="POST">
    <textarea name="comment" placeholder="Add a comment"></textarea><br>
    <button type="submit">Post Comment</button>
</form>
<h2>Comments:</h2>
<div>`)

	commentsMu.RLock()
	for _, c := range comments {
		// VULNERABLE: No escaping of stored content
		fmt.Fprintf(w, `<div class="comment">%s</div>`, c)
	}
	commentsMu.RUnlock()

	fmt.Fprintf(w, `</div>
<p><small>Try: &lt;script&gt;alert('stored')&lt;/script&gt;</small></p>
</div>
</body></html>`)
}

func fpEscaped(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		text := r.FormValue("comment")
		if text != "" {
			safeMu.Lock()
			safeComments = append(safeComments, text)
			safeMu.Unlock()
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Stored XSS - Safe Comments</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Safe Comments</h1>
<form method="POST">
    <textarea name="comment" placeholder="Add a comment"></textarea><br>
    <button type="submit">Post Comment</button>
</form>
<h2>Comments:</h2>
<div>`)

	safeMu.RLock()
	for _, c := range safeComments {
		// SAFE: Properly escaped
		fmt.Fprintf(w, `<div class="comment">%s</div>`, html.EscapeString(c))
	}
	safeMu.RUnlock()

	fmt.Fprintf(w, `</div>
<p><small>Comments are properly escaped</small></p>
</div>
</body></html>`)
}
