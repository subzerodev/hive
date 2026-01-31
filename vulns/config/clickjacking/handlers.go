package clickjacking

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/config/clickjacking/no-protection", noProtection)
		handlers.Handle("/vulns/config/clickjacking/fp/x-frame-options", fpXFrameOptions)
	})
}

func noProtection(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No clickjacking protection
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Clickjacking - Vulnerable</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Admin Panel</h1>
<form method="POST">
    <button type="submit" name="action" value="delete">Delete All Users</button>
</form>
<p><small>VULNERABLE: Can be embedded in iframe (no X-Frame-Options)</small></p>
</div>
</body></html>`)
}

func fpXFrameOptions(w http.ResponseWriter, r *http.Request) {
	// SAFE: X-Frame-Options set
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Clickjacking - Protected</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Admin Panel (Protected)</h1>
<form method="POST">
    <button type="submit" name="action" value="delete">Delete All Users</button>
</form>
<p><small>SAFE: X-Frame-Options: DENY and frame-ancestors 'none'</small></p>
</div>
</body></html>`)
}
