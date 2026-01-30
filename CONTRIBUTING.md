# Contributing Test Cases to HIVE

This guide explains how to add new vulnerability test cases to HIVE.

## Project Structure

```
hive/
├── vulns/                      # All vulnerability test cases
│   ├── injection/              # Category folder
│   │   ├── sqli/               # Subcategory folder
│   │   │   ├── mysql/          # Specific variant
│   │   │   │   ├── handlers.go # Go handlers for endpoints
│   │   │   │   └── index.html  # Navigation page
│   │   │   └── ...
│   │   └── index.html          # Category navigation
│   └── index.html              # Root navigation
├── static/                     # Static files (backdoors, configs, etc.)
├── handlers/                   # Shared handler utilities
└── main.go                     # Entry point with package imports
```

## Adding a New Test Case

### Step 1: Create the Handler File

Create a new `handlers.go` file in the appropriate category folder:

```go
// vulns/injection/newtype/handlers.go
package newtype

import (
    "fmt"
    "net/http"

    "github.com/subzerodev/hive/handlers"
)

func init() {
    handlers.Register(func() {
        // Vulnerable endpoint
        handlers.Handle("/vulns/injection/newtype/basic", basicVuln)

        // False positive (safe) endpoint
        handlers.Handle("/vulns/injection/newtype/fp/safe", fpSafe)
    })
}

// VULNERABLE: Describe the vulnerability
func basicVuln(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("input")

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>New Vulnerability Type</title></head>
<body>
<h1>Vulnerable Endpoint</h1>
<p>Input: %s</p>
<p><small>VULNERABLE: Explain why this is vulnerable</small></p>
</body></html>`, input)
}

// SAFE: Describe why this is not vulnerable
func fpSafe(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("input")

    // Proper sanitization/validation here
    sanitized := sanitize(input)

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Safe Endpoint</title></head>
<body>
<h1>Safe Endpoint (False Positive)</h1>
<p>Input: %s</p>
<p><small>SAFE: Explain the mitigation</small></p>
</body></html>`, sanitized)
}
```

### Step 2: Register the Package in main.go

Add a blank import to `main.go`:

```go
import (
    // ... existing imports ...

    _ "github.com/subzerodev/hive/vulns/injection/newtype"
)
```

### Step 3: Create Navigation Page (Optional)

If your test case has multiple variants, create an `index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>New Vulnerability Type - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
        .vuln { color: #c00; }
        .safe { color: #080; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>New Vulnerability Type</h1>

    <h2 class="vuln">Vulnerable Test Cases</h2>
    <ul>
        <li><a href="/vulns/injection/newtype/basic">Basic</a> - Description</li>
        <li><a href="/vulns/injection/newtype/variant">Variant</a> - Description</li>
    </ul>

    <h2 class="safe">False Positives (Safe)</h2>
    <ul>
        <li><a href="/vulns/injection/newtype/fp/safe">Safe Implementation</a></li>
    </ul>
</body>
</html>
```

### Step 4: Update Parent Index

Add a link to your new test case in the parent category's `index.html`.

### Step 5: Build and Test

```bash
# Rebuild Docker image
docker compose build hive

# Restart container
docker compose up -d hive

# Test your endpoint
curl http://localhost:8080/vulns/injection/newtype/basic
```

## Adding a Sub-Test Case

To add a variant to an existing category, edit the existing `handlers.go`:

```go
// In vulns/injection/sqli/mysql/handlers.go

func init() {
    handlers.Register(func() {
        // Existing handlers...
        handlers.Handle("/vulns/injection/sqli/mysql/error-based", errorBased)

        // Add your new variant
        handlers.Handle("/vulns/injection/sqli/mysql/new-variant", newVariant)
    })
}

func newVariant(w http.ResponseWriter, r *http.Request) {
    // Implementation
}
```

Then update the category's `index.html` to include the new link.

## Conventions

### URL Structure

```
/vulns/{category}/{subcategory}/{variant}
/vulns/{category}/{subcategory}/fp/{safe-variant}
```

Examples:
- `/vulns/injection/sqli/mysql/error-based`
- `/vulns/injection/sqli/mysql/fp/parameterized`
- `/vulns/xss/reflected/html-body`
- `/vulns/xss/reflected/fp/escaped`

### Handler Patterns

**Vulnerable endpoints** should:
- Clearly demonstrate the vulnerability
- Include a comment explaining the vulnerability
- Show the vulnerable behavior in the HTML response
- Use `<small>VULNERABLE: reason</small>` in output

**False positive endpoints** should:
- Implement proper security controls
- Include a comment explaining the mitigation
- Use `<small>SAFE: reason</small>` in output
- Be placed under `/fp/` path

### Query Parameters

Use consistent parameter names:
- `id` - for ID-based lookups
- `input` - for general input
- `name`, `user`, `username` - for user-related input
- `file`, `path` - for file operations
- `url` - for URL-based tests
- `q`, `query`, `search` - for search functionality

### Response Format

Always set appropriate `Content-Type` header:

```go
w.Header().Set("Content-Type", "text/html")        // HTML pages
w.Header().Set("Content-Type", "application/json") // JSON APIs
w.Header().Set("Content-Type", "text/xml")         // XML responses
```

### Database Access

For SQL injection tests, use the shared database connections:

```go
import "github.com/subzerodev/hive/db"

// Use appropriate database
rows, err := db.MySQL.Query(query)
rows, err := db.Postgres.Query(query)
rows, err := db.MSSQL.Query(query)
rows, err := db.SQLite.Query(query)
```

## Static Files

For file-based vulnerabilities (backdoors, configs, etc.), add files to `static/`:

```
static/
├── backdoors/          # PHP shells, webshells
├── exposed-configs/    # .env, config files
├── private-keys/       # RSA, SSH keys
└── ...
```

Update `static/index.html` to link to new files.

## Testing Your Changes

1. **Build and run:**
   ```bash
   docker compose build hive && docker compose up -d hive
   ```

2. **Verify endpoint works:**
   ```bash
   curl -v http://localhost:8080/vulns/your/new/endpoint
   ```

3. **Check for 404s:**
   ```bash
   # Should return 200, not 404
   curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/vulns/your/new/endpoint
   ```

4. **Run full test suite (optional):**
   ```bash
   # If you have Playwright installed
   node /path/to/playwright-test-all-vulns.js
   ```

## Commit Message Format

Use conventional commits:

```
feat: add new vulnerability test case for X

- Add basic vulnerable endpoint
- Add false positive endpoint
- Update category index
```

## Checklist

Before submitting:

- [ ] Handler file created with `init()` function
- [ ] Package imported in `main.go`
- [ ] Vulnerable endpoint demonstrates the vulnerability
- [ ] False positive endpoint shows proper mitigation
- [ ] Navigation index updated
- [ ] Docker build succeeds
- [ ] Endpoint returns 200 OK
- [ ] HTML output includes vulnerability/safety explanation
