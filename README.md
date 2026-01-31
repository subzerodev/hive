# HIVE

**Hazardous Intentionally Vulnerable Environment**

A vulnerability testbed for validating web application security scanners. HIVE provides a comprehensive collection of intentionally vulnerable endpoints across multiple vulnerability categories, along with "false positive" (safe) variants for testing scanner accuracy.

## Quick Start

```bash
# Build
go build -o hive .

# Run (SQLite only, no auth)
./hive

# Run with external databases
export MYSQL_DSN="user:pass@tcp(localhost:3306)/hive"
export POSTGRES_DSN="postgres://user:pass@localhost:5432/hive?sslmode=disable"
export MSSQL_DSN="sqlserver://sa:Password@localhost:1433?database=hive"
./hive

# Run with authentication enabled
AUTH_TYPE=form-post ./hive
```

The application starts on port **8080** by default. Visit http://localhost:8080 to browse vulnerability categories.

## Using Docker

```bash
docker-compose up -d
```

This starts HIVE with MySQL, PostgreSQL, and MSSQL containers for comprehensive SQL injection testing.

## Vulnerability Categories

| Category | Path | Description |
|----------|------|-------------|
| Injection | `/vulns/injection/` | SQLi (MySQL, PostgreSQL, MSSQL, SQLite), Command, XPath, SSTI, Code, XXE, HPP, LDAP, SSI, SSJS, CSS |
| XSS | `/vulns/xss/` | Reflected, DOM, Stored, Blacklist bypass, Context-specific, Header-based |
| File/Path | `/vulns/file/` | Path traversal, File upload, Source disclosure |
| Auth/Session | `/vulns/auth-session/` | CSRF, Cookie flags, Password exposure, Session in URL, Auth bypass |
| Info Disclosure | `/vulns/info-disclosure/` | Error messages, PII leakage, Version disclosure |
| Disclosure | `/vulns/disclosure/` | Private IPs, Private keys, JWT secrets, Database strings, Directory listing |
| Configuration | `/vulns/config/` | CORS, CSP, Clickjacking, Security headers, Host header injection |
| Serialization | `/vulns/serialization/` | Insecure deserialization |
| SSRF | `/vulns/ssrf/` | HTTP SSRF, DNS SSRF, OOB variants |
| Open Redirect | `/vulns/redirect/` | Location, Meta refresh, JavaScript redirects |
| Form Hijacking | `/vulns/formhijack/` | Action manipulation, Hidden fields, Link manipulation |
| Sensitive Files | `/vulns/files/` | Backups, .git exposure, .env files, Debug pages |
| Admin Interfaces | `/vulns/admin/` | Generic admin, CMS admin, Framework debug modes |
| HTTP Methods | `/vulns/methods/` | PUT, TRACE, DELETE, OPTIONS |
| Legacy | `/vulns/legacy/` | Flash, Silverlight, ASP.NET ViewState, Perl, Ruby, Python |

Each category contains both **vulnerable** endpoints and **false positive (fp)** endpoints that implement proper security controls.

## Authentication Types

HIVE supports gating the entire application behind different authentication mechanisms. Set the `AUTH_TYPE` environment variable to enable:

| AUTH_TYPE | Description | How It Works |
|-----------|-------------|--------------|
| `none` | No authentication (default) | All endpoints accessible |
| `form-post` | Traditional form login | Cookie `session_formpost=authenticated_admin` |
| `ajax-json` | AJAX/JSON API login | Cookie `session_ajax=authenticated_admin` |
| `multi-step` | Multi-step authentication | Cookie `session_multistep=authenticated_admin` |
| `oauth` | OAuth flow simulation | Cookie `session_oauth=authenticated_admin` |
| `http-basic` | HTTP Basic Authentication | `Authorization: Basic` header (admin:password) |
| `jwt` | JWT Bearer token | `Authorization: Bearer <token>` header |

### Authentication Behavior

When authentication is enabled:
- All `/vulns/*` routes require authentication **except** `/vulns/auth/*` (login pages)
- Unauthenticated requests receive auth-type-appropriate responses:
  - Cookie-based types: `302` redirect to login page
  - `http-basic`: `401` with `WWW-Authenticate: Basic` header
  - `jwt`: `401` with `WWW-Authenticate: Bearer` header

### Login Endpoints

| Auth Type | Login Page | Credentials |
|-----------|------------|-------------|
| form-post | `/vulns/auth/formpost/` | admin / password |
| ajax-json | `/vulns/auth/ajaxjson/` | admin / password |
| multi-step | `/vulns/auth/multistep/` | admin / password + code: 123456 |
| oauth | `/vulns/auth/oauth/` | Click authorize |
| http-basic | Browser prompt | admin / password |
| jwt | `/vulns/auth/jwt/` | admin / password |

### JWT Token Format

JWT tokens must be HS256-signed with the secret `supersecretkey` and include:
- `sub`: Username
- `exp`: Expiration timestamp (must be in the future)

Example payload:
```json
{
  "sub": "admin",
  "exp": 1893456000
}
```

### Session Validation Endpoints

Each auth type exposes a `/session` endpoint for programmatic session checking:

```bash
# Check if authenticated
curl http://localhost:8080/vulns/auth/formpost/session \
  -H "Cookie: session_formpost=authenticated_admin"
# Returns: {"authenticated": true}

# JWT session check
curl http://localhost:8080/vulns/auth/jwt/session \
  -H "Authorization: Bearer <token>"
# Returns: {"authenticated": true, "user": "admin"}
```

## Adding New Test Cases

### Directory Structure

```
vulns/
├── category/
│   ├── index.html          # Category landing page
│   └── subcategory/
│       ├── index.html      # Subcategory landing page
│       └── handlers.go     # Go handler implementations

templates/
├── base.html               # Base layout (head, CSS, container)
├── templates.go            # Render helper and Page struct
└── vulns/
    └── category/
        └── subcategory/
            ├── vulnerable.html
            └── fp/safe.html
```

### Creating a New Vulnerability Handler

HIVE uses Go's `html/template` package with a base layout for cleaner handler code.

1. **Create the template files:**

   Create `templates/vulns/category/subcategory/vulnerable.html`:
   ```html
   {{define "content"}}
   <form method="GET">
       <input name="input" value="{{.FormValue}}" placeholder="Input">
       <button type="submit">Submit</button>
   </form>
   <div class="result">Result: {{.OutputRaw}}</div>
   <p><small>Try: &lt;script&gt;alert(1)&lt;/script&gt;</small></p>
   {{end}}
   ```

   Create `templates/vulns/category/subcategory/fp/safe.html`:
   ```html
   {{define "content"}}
   <form method="GET">
       <input name="input" value="{{.FormValue}}" placeholder="Input">
       <button type="submit">Submit</button>
   </form>
   <div class="result">Result: {{.Output}}</div>
   <p><small>Input is properly escaped</small></p>
   {{end}}
   ```

2. **Create `handlers.go`:**
   ```go
   package subcategory

   import (
       "html"
       "html/template"
       "net/http"

       "github.com/subzerodev/hive/handlers"
       "github.com/subzerodev/hive/templates"
   )

   func init() {
       handlers.Register(func() {
           handlers.Handle("/vulns/category/subcategory/vulnerable", vulnerable)
           handlers.Handle("/vulns/category/subcategory/fp/safe", fpSafe)
       })
   }

   func vulnerable(w http.ResponseWriter, r *http.Request) {
       input := r.URL.Query().Get("input")

       w.Header().Set("Content-Type", "text/html")
       templates.Render(w, "category/subcategory/vulnerable", templates.Page{
           Title:     "Vulnerable Endpoint",
           Heading:   "Vulnerable Endpoint",
           FormValue: html.EscapeString(input),
           OutputRaw: template.HTML(input), // VULNERABLE: unescaped
       })
   }

   func fpSafe(w http.ResponseWriter, r *http.Request) {
       input := r.URL.Query().Get("input")
       escaped := html.EscapeString(input)

       w.Header().Set("Content-Type", "text/html")
       templates.Render(w, "category/subcategory/fp/safe", templates.Page{
           Title:     "Safe Endpoint",
           Heading:   "Safe Endpoint (False Positive)",
           FormValue: escaped,
           Output:    escaped, // SAFE: escaped
       })
   }
   ```

3. **Register the import in `main.go`:**
   ```go
   import (
       // ... existing imports ...
       _ "hive/vulns/category/subcategory"
   )
   ```

4. **Create `index.html` for the category page:**
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <meta charset="UTF-8">
       <title>Subcategory - HIVE</title>
       <link rel="stylesheet" href="/static/css/hive.css">
   </head>
   <body>
       <div class="container">
           <div class="back"><a href="..">&larr; Back</a></div>
           <h1>Subcategory Vulnerabilities</h1>
           <ul>
               <li><a href="vulnerable">Vulnerable Endpoint</a> <span class="vuln">[VULN]</span></li>
               <li><a href="fp/safe">Safe Endpoint</a> <span class="safe">[FP]</span></li>
           </ul>
       </div>
   </body>
   </html>
   ```

### Naming Conventions

- **Vulnerable endpoints:** Descriptive names (`error-based`, `blind-boolean`, `reflected`)
- **Safe endpoints:** Prefix with `fp/` (`fp/parameterized`, `fp/escaped`, `fp/validated`)
- **Package names:** Lowercase, no underscores (`sqli`, `pathtraversal`, `errormessages`)

### Handler Patterns

**SQL Injection:**
```go
// Vulnerable - string concatenation
query := "SELECT * FROM users WHERE id = " + id
db.Query(query)

// Safe - parameterized query
db.Query("SELECT * FROM users WHERE id = ?", id)
```

**XSS:**
```go
// Vulnerable - use OutputRaw (template.HTML bypasses escaping)
templates.Render(w, "path/to/template", templates.Page{
    OutputRaw: template.HTML(userInput),
})

// Safe - use Output (auto-escaped by template engine)
templates.Render(w, "path/to/template", templates.Page{
    Output: userInput,
})
```

**Command Injection:**
```go
// Vulnerable - shell execution
exec.Command("sh", "-c", "ping " + host).Output()

// Safe - direct execution without shell
exec.Command("ping", "-c", "1", host).Output()
```

### Database Access

Use the global database connections for SQL injection tests:

```go
import "hive/db"

// MySQL
rows, err := db.MySQL.Query("SELECT * FROM users WHERE id = " + id)

// PostgreSQL
rows, err := db.Postgres.Query("SELECT * FROM users WHERE id = $1", id)

// MSSQL
rows, err := db.MSSQL.Query("SELECT * FROM users WHERE id = @p1", sql.Named("p1", id))

// SQLite (always available)
rows, err := db.SQLite.Query("SELECT * FROM users WHERE id = " + id)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (returns "OK") |
| `/api/reset` | POST | Reset all databases to initial state |

## Architecture

```
hive/
├── main.go              # Entry point, routing, static files
├── handlers/
│   └── handlers.go      # Handler registration system
├── templates/
│   ├── base.html        # Base layout template
│   ├── templates.go     # Render() helper and Page struct
│   └── vulns/           # Content templates for handlers
├── auth/
│   ├── middleware.go    # Auth middleware dispatcher
│   └── validators.go    # Auth type validators
├── db/
│   └── db.go            # Database connections and init
├── api/
│   └── reset.go         # Database reset endpoint
├── vulns/               # Vulnerability test cases
│   ├── index.html       # Main landing page
│   └── {category}/      # Vulnerability categories
├── static/
│   ├── css/hive.css     # Shared stylesheet
│   └── ...              # Static test files
└── seed/
    └── data.go          # Database seed data
```

### Handler Registration

Handlers self-register using the `init()` pattern:

```go
func init() {
    handlers.Register(func() {
        handlers.Handle("/path", handlerFunc)
    })
}
```

This enables automatic discovery - just import the package in `main.go` and routes are registered.

### Auth Middleware Flow

```
Request → Auth Middleware → Handler
              ↓
    Check AUTH_TYPE env var
              ↓
    If "/vulns/auth/*" → Allow (login pages)
              ↓
    Validate session/token for auth type
              ↓
    If valid → Allow
    If invalid → Return auth-appropriate error
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_TYPE` | Authentication type | `none` |
| `MYSQL_DSN` | MySQL connection string | (disabled) |
| `POSTGRES_DSN` | PostgreSQL connection string | (disabled) |
| `MSSQL_DSN` | MSSQL connection string | (disabled) |
| `SQLITE_PATH` | SQLite database path | `hive.db` |

## Testing Scanner Accuracy

HIVE is designed to test both **true positive** (vulnerability detection) and **false positive** (safe code incorrectly flagged) rates:

1. **Run your scanner against HIVE**
2. **Compare results:**
   - Vulnerabilities in non-`fp/` paths should be detected (true positives)
   - Endpoints in `fp/` paths should NOT be flagged (false positives indicate scanner issues)

Example test matrix:
```
/vulns/xss/reflected/html-body     → Should detect XSS
/vulns/xss/reflected/fp/escaped    → Should NOT detect XSS
/vulns/injection/sqli/sqlite/error-based    → Should detect SQLi
/vulns/injection/sqli/sqlite/fp/parameterized → Should NOT detect SQLi
```

## License

This software is provided for authorized security testing and educational purposes only.
