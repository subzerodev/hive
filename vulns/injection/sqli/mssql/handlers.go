// vulns/injection/sqli/mssql/handlers.go
package mssql

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/sqli/mssql/error-based", errorBased)
		handlers.Handle("/vulns/injection/sqli/mssql/union-based", unionBased)
		handlers.Handle("/vulns/injection/sqli/mssql/blind-boolean", blindBoolean)
		handlers.Handle("/vulns/injection/sqli/mssql/blind-time", blindTime)
		handlers.Handle("/vulns/injection/sqli/mssql/fp/parameterized", fpParameterized)
	})
}

func errorBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>MSSQL Error-Based SQLi</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	if db.MSSQL == nil {
		fmt.Fprintf(w, "MSSQL not connected")
	} else {
		query := "SELECT id, username, email FROM users WHERE id = " + id
		rows, err := db.MSSQL.Query(query)
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err.Error())
		} else {
			defer rows.Close()
			for rows.Next() {
				var uid int
				var username, email string
				rows.Scan(&uid, &username, &email)
				fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
			}
		}
	}

	fmt.Fprintf(w, `</pre>
</div>
</body></html>`)
}

func unionBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>MSSQL Union-Based SQLi</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Product Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="Product ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	if db.MSSQL == nil {
		fmt.Fprintf(w, "MSSQL not connected")
	} else {
		query := "SELECT id, name, description FROM products WHERE id = " + id
		rows, err := db.MSSQL.Query(query)
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err.Error())
		} else {
			defer rows.Close()
			for rows.Next() {
				var pid int
				var name, desc string
				rows.Scan(&pid, &name, &desc)
				fmt.Fprintf(w, "ID: %d, Name: %s, Description: %s\n", pid, name, desc)
			}
		}
	}

	fmt.Fprintf(w, `</pre>
</div>
</body></html>`)
}

func blindBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	found := false
	if db.MSSQL != nil {
		query := "SELECT username FROM users WHERE id = " + id
		var username string
		err := db.MSSQL.QueryRow(query).Scan(&username)
		found = err == nil
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>MSSQL Blind Boolean SQLi</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User Exists Check</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Check</button>
</form>
<h2>Result:</h2>`, id)

	if found {
		fmt.Fprintf(w, `<p>User exists!</p>`)
	} else {
		fmt.Fprintf(w, `<p>User not found.</p>`)
	}

	fmt.Fprintf(w, `</div>
</body></html>`)
}

func blindTime(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	if db.MSSQL != nil {
		query := "SELECT username FROM users WHERE id = " + id
		var username string
		db.MSSQL.QueryRow(query).Scan(&username)
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>MSSQL Blind Time SQLi</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User Lookup (Time-based)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Result:</h2>
<p>Query completed.</p>
<p><small>Try: 1; WAITFOR DELAY '0:0:5'--</small></p>
</div>
</body></html>`, id)
}

func fpParameterized(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>MSSQL Parameterized (Safe)</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>User Lookup (Safe)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	if db.MSSQL == nil {
		fmt.Fprintf(w, "MSSQL not connected")
	} else {
		// SAFE: Parameterized query (MSSQL uses @p1, @p2, etc.)
		rows, err := db.MSSQL.Query("SELECT id, username, email FROM users WHERE id = @p1", id)
		if err != nil {
			fmt.Fprintf(w, "Error: query failed")
		} else {
			defer rows.Close()
			for rows.Next() {
				var uid int
				var username, email string
				rows.Scan(&uid, &username, &email)
				fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
			}
		}
	}

	fmt.Fprintf(w, `</pre>
</div>
</body></html>`)
}
