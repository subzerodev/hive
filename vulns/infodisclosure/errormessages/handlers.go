package errormessages

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/info-disclosure/error-messages/database", database)
		handlers.Handle("/vulns/info-disclosure/error-messages/stack-trace", stackTrace)
		handlers.Handle("/vulns/info-disclosure/error-messages/fp/generic", fpGeneric)
	})
}

func database(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Database Error Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Result:</h2>
<pre>`, id)

	// VULNERABLE: Expose database errors
	query := "SELECT * FROM users WHERE id = " + id
	var username, email string

	if db.MySQL != nil {
		err := db.MySQL.QueryRow(query).Scan(&username, &email)
		if err != nil {
			// VULNERABLE: Full error message exposed
			fmt.Fprintf(w, "Database Error: %v\nQuery: %s", err, query)
		} else {
			fmt.Fprintf(w, "User: %s (%s)", username, email)
		}
	} else {
		fmt.Fprintf(w, "Database not available - simulated error:\nError 1064: You have an error in your SQL syntax near '%s'", id)
	}

	fmt.Fprintf(w, `</pre>
<p><small>VULNERABLE: Database error messages exposed</small></p>
<p><small>Try: ' OR 1=1--</small></p>
</div>
</body></html>`)
}

func stackTrace(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Stack Trace Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Action Handler</h1>
<form method="GET">
    <select name="action">
        <option value="">Select action</option>
        <option value="profile">View Profile</option>
        <option value="error">Trigger Error</option>
    </select>
    <button type="submit">Execute</button>
</form>
<h2>Result:</h2>
<pre>`)

	if action == "error" {
		// VULNERABLE: Full stack trace exposed
		fmt.Fprintf(w, `Internal Server Error

Exception: java.lang.NullPointerException
    at com.hive.UserController.getProfile(UserController.java:142)
    at com.hive.UserController.handleRequest(UserController.java:87)
    at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)
    at javax.servlet.http.HttpServlet.service(HttpServlet.java:750)
    at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:231)

Server: Apache Tomcat/9.0.50
Java Version: 11.0.11
Framework: Spring Boot 2.5.4`)
	} else if action == "profile" {
		fmt.Fprintf(w, "Profile loaded successfully.")
	} else {
		fmt.Fprintf(w, "Select an action above.")
	}

	fmt.Fprintf(w, `</pre>
<p><small>VULNERABLE: Stack trace and version info in errors</small></p>
</div>
</body></html>`)
}

func fpGeneric(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Generic Error Page</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Result:</h2>
<pre>`, id)

	// SAFE: Generic error message
	if id == "1" {
		fmt.Fprintf(w, "User: admin (admin@hive.local)")
	} else {
		fmt.Fprintf(w, "An error occurred. Please try again later.")
	}

	fmt.Fprintf(w, `</pre>
<p><small>SAFE: Generic error messages, no technical details</small></p>
</div>
</body></html>`)
}
