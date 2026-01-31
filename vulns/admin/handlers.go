// vulns/admin/handlers.go
package admin

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Generic admin interfaces
		handlers.Handle("/vulns/admin/login", adminLogin)
		handlers.Handle("/vulns/admin/dashboard", adminDashboard)
		handlers.Handle("/vulns/admin/console", adminConsole)

		// CMS-specific
		handlers.Handle("/vulns/admin/wp-admin", wpAdmin)
		handlers.Handle("/vulns/admin/wp-login", wpLogin)
		handlers.Handle("/vulns/admin/phpmyadmin", phpMyAdmin)

		// Framework-specific
		handlers.Handle("/vulns/admin/actuator", springActuator)
		handlers.Handle("/vulns/admin/actuator/env", springEnv)
		handlers.Handle("/vulns/admin/actuator/health", springHealth)
		handlers.Handle("/vulns/admin/laravel-debugbar", laravelDebugbar)

		// False positive
		handlers.Handle("/vulns/admin/fp/protected", fpProtected)

		// WordPress user enumeration
		handlers.Handle("/vulns/admin/wp-user-enum", wpUserEnum)
		handlers.Handle("/vulns/admin/wp-user-enum/author", wpUserEnumAuthor)
		handlers.Handle("/vulns/admin/wp-user-enum/api", wpUserEnumAPI)
		handlers.Handle("/vulns/admin/wp-user-enum/fp/blocked", wpUserEnumBlocked)
	})
}

func adminLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Admin Login</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Administrator Login</h1>
<form method="POST" action="/vulns/admin/login">
    <input name="username" placeholder="Username"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <button type="submit">Login</button>
</form>
<p><small>Default credentials: admin / admin</small></p>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func adminDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Admin Dashboard</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Administration Dashboard</h1>
<h2>Quick Stats:</h2>
<ul>
    <li>Users: 1,234</li>
    <li>Orders: 5,678</li>
    <li>Revenue: $123,456</li>
</ul>
<h2>System Info:</h2>
<pre>
Server: Apache/2.4.52
PHP: 8.1.0
MySQL: 8.0.32
</pre>
<h2>Admin Actions:</h2>
<ul>
    <li><a href="/vulns/admin/users">Manage Users</a></li>
    <li><a href="/vulns/admin/settings">System Settings</a></li>
    <li><a href="/vulns/admin/logs">View Logs</a></li>
</ul>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func adminConsole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Admin Console</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Administrator Console</h1>
<h2>Command Execution:</h2>
<form method="POST">
    <input name="command" placeholder="Enter command" style="width:300px">
    <button type="submit">Execute</button>
</form>
<h2>Database Query:</h2>
<form method="POST">
    <textarea name="query" rows="4" cols="50" placeholder="SELECT * FROM users"></textarea><br>
    <button type="submit">Run Query</button>
</form>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func wpAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>WordPress Admin</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>WordPress Dashboard</h1>
<div>
    <h2>Welcome to WordPress!</h2>
    <p>WordPress Version: 6.4.2</p>
</div>
<h2>At a Glance:</h2>
<ul>
    <li>5 Posts</li>
    <li>3 Pages</li>
    <li>12 Comments</li>
</ul>
<h2>Quick Actions:</h2>
<ul>
    <li><a href="#">Write a new post</a></li>
    <li><a href="#">Manage plugins</a></li>
    <li><a href="#">Appearance</a></li>
</ul>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func wpLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Log In - WordPress</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
    <h1>WordPress</h1>
    <form method="POST">
        <p>
            <label>Username or Email Address</label><br>
            <input name="log">
        </p>
        <p>
            <label>Password</label><br>
            <input type="password" name="pwd">
        </p>
        <p>
            <input type="checkbox" name="rememberme"> Remember Me
        </p>
        <p>
            <button type="submit">Log In</button>
        </p>
    </form>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func phpMyAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>phpMyAdmin</h1>
<h2>Database Server:</h2>
<pre>
Server: localhost via UNIX socket
Server version: 8.0.32 - MySQL Community Server
Protocol version: 10
User: root@localhost
</pre>
<h2>Databases:</h2>
<ul>
    <li>information_schema</li>
    <li>mysql</li>
    <li>performance_schema</li>
    <li>production_db</li>
    <li>wordpress</li>
</ul>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func springActuator(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
  "_links": {
    "self": {"href": "/vulns/admin/actuator"},
    "health": {"href": "/vulns/admin/actuator/health"},
    "env": {"href": "/vulns/admin/actuator/env"},
    "beans": {"href": "/vulns/admin/actuator/beans"},
    "mappings": {"href": "/vulns/admin/actuator/mappings"},
    "heapdump": {"href": "/vulns/admin/actuator/heapdump"},
    "threaddump": {"href": "/vulns/admin/actuator/threaddump"}
  }
}`)
}

func springEnv(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
  "activeProfiles": ["production"],
  "propertySources": [
    {
      "name": "systemEnvironment",
      "properties": {
        "DB_PASSWORD": {"value": "ProductionDbPass123!"},
        "API_SECRET": {"value": "sk-live-secret-key-xyz"},
        "AWS_ACCESS_KEY_ID": {"value": "AKIAIOSFODNN7EXAMPLE"},
        "AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
      }
    },
    {
      "name": "applicationConfig",
      "properties": {
        "spring.datasource.url": {"value": "jdbc:mysql://db.internal:3306/prod"},
        "spring.datasource.username": {"value": "app_user"},
        "spring.datasource.password": {"value": "******"}
      }
    }
  ]
}`)
}

func springHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
  "status": "UP",
  "components": {
    "db": {
      "status": "UP",
      "details": {
        "database": "MySQL",
        "validationQuery": "isValid()"
      }
    },
    "diskSpace": {
      "status": "UP",
      "details": {
        "total": 107374182400,
        "free": 85899345920,
        "path": "/var/www/app"
      }
    },
    "redis": {
      "status": "UP",
      "details": {
        "version": "7.0.0"
      }
    }
  }
}`)
}

func laravelDebugbar(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Laravel Debugbar</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Laravel Debugbar</h1>
<h2>Request Info:</h2>
<pre>
Route: GET /api/users
Controller: App\Http\Controllers\UserController@index
Middleware: api, auth:sanctum
</pre>
<h2>Queries (5 queries):</h2>
<pre>
SELECT * FROM users WHERE active = 1 [2.5ms]
SELECT * FROM roles WHERE id IN (1, 2, 3) [1.2ms]
SELECT * FROM permissions [0.8ms]
</pre>
<h2>Session:</h2>
<pre>
user_id: 1
api_token: sk-live-token-12345
admin: true
</pre>
<h2>Environment:</h2>
<pre>
APP_KEY=base64:abc123...
DB_PASSWORD=LaravelDbPass!
</pre>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func fpProtected(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("WWW-Authenticate", "Basic realm=\"Admin\"")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>401 Unauthorized</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>401 Unauthorized</h1>
<p>Authentication required to access this resource.</p>
<h3>Security:</h3>
<p><small>SAFE: Admin interface requires authentication</small></p>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

// WordPress User Enumeration
func wpUserEnum(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>WordPress User Enumeration</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>WordPress User Enumeration</h1>
<p>Multiple methods to enumerate WordPress usernames.</p>

<h2>Enumeration Methods:</h2>
<ul>
    <li><a href="/vulns/admin/wp-user-enum/author?author=1">Author Parameter</a> - /?author=1</li>
    <li><a href="/vulns/admin/wp-user-enum/api">REST API</a> - /wp-json/wp/v2/users</li>
</ul>

<h2>Discovered Users:</h2>
<table border="1" cellpadding="5">
    <tr><th>ID</th><th>Username</th><th>Display Name</th></tr>
    <tr><td>1</td><td>admin</td><td>Administrator</td></tr>
    <tr><td>2</td><td>editor</td><td>John Editor</td></tr>
    <tr><td>3</td><td>author1</td><td>Jane Author</td></tr>
</table>

<h3>Vulnerability:</h3>
<p><small>WordPress username enumeration enables targeted attacks</small></p>
<p><a href="/vulns/admin/">Back to Admin Tests</a></p>
</div>
</body></html>`)
}

func wpUserEnumAuthor(w http.ResponseWriter, r *http.Request) {
	author := r.URL.Query().Get("author")
	if author == "" {
		author = "1"
	}

	username := "admin"
	switch author {
	case "1":
		username = "admin"
	case "2":
		username = "editor"
	case "3":
		username = "author1"
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Author not found")
		return
	}

	w.Header().Set("Location", "/author/"+username+"/")
	w.WriteHeader(http.StatusMovedPermanently)
	fmt.Fprintf(w, `Redirecting to /author/%s/ (username: %s)`, username, username)
}

func wpUserEnumAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `[
  {"id": 1, "name": "Administrator", "slug": "admin", "link": "http://localhost:8080/author/admin/"},
  {"id": 2, "name": "John Editor", "slug": "editor", "link": "http://localhost:8080/author/editor/"},
  {"id": 3, "name": "Jane Author", "slug": "author1", "link": "http://localhost:8080/author/author1/"}
]`)
}

func wpUserEnumBlocked(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"code": "rest_user_cannot_view", "message": "Sorry, you are not allowed to list users."}`)
}
