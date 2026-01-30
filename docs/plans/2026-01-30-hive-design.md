# HIVE - Hazardous Intentionally Vulnerable Environment

A Go-based vulnerability testbed for validating web vulnerability scanners.

## Overview

HIVE provides comprehensive test cases covering all vulnerability types from EVWA and VECTOR, organized for easy navigation and extensibility. It replaces the PHP/Apache stack with a single Go binary for simpler deployment and full control over HTTP behavior.

### Core Principles

- **Standalone test cases** - No framework getting in the way of vulnerabilities
- **File-based convention** - Drop a folder to add a test case
- **Hybrid serving** - Go for dynamic vulns, real files for file-based tests
- **Multi-database** - MySQL, PostgreSQL, MSSQL, SQLite for SQLi testing
- **Toggleable auth** - 6 auth types for testing scanner login handling
- **CI-ready** - Docker-first, designed for pipeline integration

### Deployment

- Local: `docker-compose up`
- CI: Same, with programmatic reset API for clean state between runs

## Folder Structure

```
hive/
├── main.go                     # Entry point, router setup
├── docker-compose.yml          # All services (app + databases)
├── Dockerfile
├── config/
│   └── config.go               # Auth toggle, DB connections
├── seed/
│   ├── mysql.sql
│   ├── postgres.sql
│   ├── mssql.sql
│   └── sqlite.sql
├── static/                     # Real files for file-based tests
│   ├── directory-listing/
│   ├── backup-files/
│   ├── exposed-configs/
│   ├── private-keys/
│   └── common-files/
├── vulns/                      # All vulnerability test cases
│   ├── index.html              # Main landing page
│   ├── injection/
│   ├── xss/
│   ├── file/
│   ├── auth-session/
│   ├── info-disclosure/
│   ├── config/
│   ├── serialization/
│   ├── ssrf/
│   ├── backdoors/
│   └── auth/
└── handlers/                   # Shared handler utilities
    └── utils.go
```

Each test case folder contains:
- `handler.go` - The vulnerable endpoint
- `index.html` - Optional, for multi-variant test cases
- `expected.yaml` - Optional, for future CI regression testing

## Test Case Handler Pattern

Each test case is a standalone Go file that registers itself via `init()`:

```go
// vulns/injection/sqli/mysql/error-based/handler.go
package main

import (
    "database/sql"
    "net/http"
)

func init() {
    http.HandleFunc("/vulns/injection/sqli/mysql/error-based", func(w http.ResponseWriter, r *http.Request) {
        id := r.URL.Query().Get("id")

        // Vulnerable: direct string concatenation
        query := "SELECT * FROM users WHERE id = " + id
        rows, err := mysqlDB.Query(query)

        if err != nil {
            // Leak error message (intentional)
            w.Write([]byte(err.Error()))
            return
        }
        // ... render results
    })
}
```

### False Positive Variant

```go
// vulns/injection/sqli/mysql/fp/parameterized/handler.go
func init() {
    http.HandleFunc("/vulns/injection/sqli/mysql/fp/parameterized", func(w http.ResponseWriter, r *http.Request) {
        id := r.URL.Query().Get("id")

        // Safe: parameterized query
        rows, err := mysqlDB.Query("SELECT * FROM users WHERE id = ?", id)
        // ...
    })
}
```

At startup, Go's `init()` functions auto-register all handlers. No config file to maintain.

## Database Setup

Docker-compose spins up all databases with seeded test data:

```yaml
services:
  hive:
    build: .
    ports:
      - "8080:8080"
    environment:
      - AUTH_TYPE=none
    depends_on:
      - mysql
      - postgres
      - mssql

  mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: hive
      MYSQL_DATABASE: hive
    volumes:
      - ./seed/mysql.sql:/docker-entrypoint-initdb.d/init.sql

  postgres:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: hive
      POSTGRES_DB: hive
    volumes:
      - ./seed/postgres.sql:/docker-entrypoint-initdb.d/init.sql

  mssql:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: Y
      SA_PASSWORD: Hive_Password1
    volumes:
      - ./seed/mssql.sql:/seed.sql
```

SQLite is embedded - no container needed.

### Seed Data

Each database contains:
- `users` - id, username, password, email
- `products` - id, name, description, price
- `comments` - id, user_id, content, created_at

### Reset API

```
POST /api/reset  →  Re-seeds all databases to clean state
```

## Authentication System

Auth is controlled via environment variable:

| AUTH_TYPE | Description |
|-----------|-------------|
| `none` | No auth, everything open (default) |
| `form-post` | Traditional form login |
| `ajax-json` | SPA-style API login |
| `multi-step` | Username page → password page |
| `oauth` | Fake OAuth provider redirect flow |
| `http-basic` | Browser auth dialog |
| `jwt` | Login returns token, use in header |

### How It Works

1. When `AUTH_TYPE` is set, middleware protects all `/vulns/*` routes
2. Login endpoints live at `/vulns/auth/{type}/login`
3. Session polling endpoint: `GET /vulns/auth/session` returns `{"valid": true/false}`
4. Credentials: `admin` / `password`

### Scanner Testing Flow

1. Record login flow with Chrome DevTools
2. Configure rapture with the recording
3. Rapture polls `/vulns/auth/session` to detect session expiry
4. Re-authenticates when needed

## Static File Handling

For file-based vulnerabilities, real files are served with directory listing enabled:

```go
http.Handle("/static/", http.StripPrefix("/static/",
    http.FileServer(http.Dir("./static"))))
```

### Static Folder Structure

```
static/
├── directory-listing/
│   ├── public/
│   │   ├── images/
│   │   ├── docs/
│   │   └── uploads/
│   └── fp/
│       └── index.html          # Has index, no listing shown
├── backup-files/
│   ├── config.php.bak
│   ├── database.sql.old
│   ├── .htaccess.save
│   ├── web.config~
│   └── fp/
│       └── readme.txt.pdf      # Looks like backup, isn't
├── exposed-configs/
│   ├── .env
│   ├── .git/config
│   ├── wp-config.php
│   └── fp/
│       └── env.example         # Template, no real secrets
├── private-keys/
│   ├── id_rsa
│   ├── server.key
│   └── fp/
│       └── id_rsa.pub          # Public key, not sensitive
└── common-files/
    ├── robots.txt
    ├── .htaccess
    ├── crossdomain.xml
    └── clientaccesspolicy.xml
```

## Vulnerability Categories

Complete breakdown of `/vulns/` structure:

### Injection

```
injection/
├── sqli/
│   ├── mysql/
│   │   ├── error-based/
│   │   ├── union-based/
│   │   ├── blind-boolean/
│   │   ├── blind-time/
│   │   └── fp/
│   ├── postgres/
│   ├── mssql/
│   └── sqlite/
├── command/
│   ├── basic/
│   ├── blind/
│   ├── out-of-band/
│   └── fp/
├── ldap/
├── xpath/
├── ssi/
├── ssti/
│   └── (twig, jinja2, freemarker, etc.)
├── code/
│   └── php/ python/ ruby/ perl/
├── xml/
│   └── xxe/ entity-expansion/ injection/
├── expression-language/
└── smtp-header/
```

### XSS

```
xss/
├── reflected/
│   ├── html-body/
│   ├── attributes/
│   ├── javascript/
│   ├── url/
│   ├── json/
│   ├── encoding/
│   ├── multi-param/
│   ├── blacklist-bypass/
│   └── fp/
├── dom/
│   ├── innerhtml/
│   ├── document-write/
│   ├── location/
│   ├── eval/
│   ├── jquery/
│   └── fp/
├── stored/
│   ├── comment/
│   ├── profile/
│   ├── mixed/
│   ├── json-api/
│   └── fp/
├── framework/
│   └── angular/ react/ vue/
└── css-injection/
```

### File/Path

```
file/
├── path-traversal/
│   ├── get/
│   ├── post/
│   ├── cookie/
│   ├── headers/
│   ├── base64/
│   └── fp/
├── upload/
│   ├── unrestricted/
│   ├── bypass-extension/
│   ├── bypass-mime/
│   └── fp/
└── source-disclosure/
```

### Auth/Session

```
auth-session/
├── csrf/
├── session-in-url/
├── cookie-flags/
│   └── httponly/ secure/ samesite/
├── password-exposure/
│   └── in-get/ in-cookie/ in-response/ autocomplete/
└── auth-bypass/
    └── 403-bypass/ header-abuse/
```

### Info Disclosure

```
info-disclosure/
├── error-messages/
│   └── mysql/ postgres/ mssql/ oracle/ mongodb/ (25+ more)
├── private-ips/
├── api-keys/
├── pii/
│   └── emails/ credit-cards/ ssn/
├── connection-strings/
├── private-keys/
├── version-disclosure/
├── api-docs/
└── sensitive-files/
```

### Configuration

```
config/
├── cors/
├── csp/
├── clickjacking/
├── http-methods/
│   └── trace/ put/
├── host-header/
├── open-redirect/
└── content-type/
```

### Other

```
serialization/
ssrf/
    └── http/ dns/
backdoors/
    └── (31 PHP variants)
```

### Authentication Testing

```
auth/
├── form-post/
├── ajax-json/
├── multi-step/
├── oauth/
├── http-basic/
└── jwt/
```

## Navigation

Each level has a hand-crafted `index.html` linking to children.

### Root Index

```html
<!DOCTYPE html>
<html>
<head><title>HIVE - Hazardous Intentionally Vulnerable Environment</title></head>
<body>
  <h1>HIVE</h1>
  <p>Hazardous Intentionally Vulnerable Environment</p>

  <h2>Vulnerability Categories</h2>
  <ul>
    <li><a href="/vulns/injection/">Injection</a></li>
    <li><a href="/vulns/xss/">Cross-Site Scripting</a></li>
    <li><a href="/vulns/file/">File/Path</a></li>
    <li><a href="/vulns/auth-session/">Auth/Session</a></li>
    <li><a href="/vulns/info-disclosure/">Info Disclosure</a></li>
    <li><a href="/vulns/config/">Configuration</a></li>
    <li><a href="/vulns/serialization/">Serialization</a></li>
    <li><a href="/vulns/ssrf/">SSRF</a></li>
    <li><a href="/vulns/backdoors/">Backdoors</a></li>
  </ul>

  <h2>Authentication Testing</h2>
  <ul>
    <li><a href="/vulns/auth/">Auth Flows</a></li>
  </ul>

  <h2>Static Files</h2>
  <ul>
    <li><a href="/static/">Directory Listing & File Tests</a></li>
  </ul>
</body>
</html>
```

Scanner crawls from root, follows all links, discovers everything.

## CI Integration

### Reset API

```go
// POST /api/reset
func handleReset(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "POST only", 405)
        return
    }

    resetMySQL()
    resetPostgres()
    resetMSSQL()
    resetSQLite()
    clearStoredData()

    w.Write([]byte(`{"status": "reset complete"}`))
}
```

### Example GitHub Actions Pipeline

```yaml
name: Scanner Regression
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start HIVE
        run: docker-compose up -d

      - name: Wait for healthy
        run: curl --retry 10 --retry-delay 2 http://localhost:8080/health

      - name: Run rapture scan
        run: rapture scan http://localhost:8080/vulns/

      - name: Reset for next scan
        run: curl -X POST http://localhost:8080/api/reset

      - name: Teardown
        run: docker-compose down
```

### Future: expected.yaml

Structure supports adding `expected.yaml` files per test case:

```yaml
# /vulns/injection/sqli/mysql/error-based/expected.yaml
detects:
  - sqli-error-based
  - sqli-mysql
```

Comparison tooling to be built when needed.

## Summary

| Aspect | Decision |
|--------|----------|
| Language | Go with net/http |
| Deployment | Docker + docker-compose |
| Databases | MySQL, PostgreSQL, MSSQL, SQLite |
| Organization | File-based convention, auto-discovered handlers |
| Test cases | Standalone, no shared layout |
| FP organization | `/fp/` subfolder within each category |
| Static files | Real files served with directory listing |
| Auth | 6 types, toggleable via `AUTH_TYPE` env var |
| Navigation | Hand-crafted index pages at each level |
| CI | Reset API, designed for expected.yaml later |
| Vuln coverage | Full EVWA + VECTOR list (~100 categories) |
