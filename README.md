# HIVE

**Hazardous Intentionally Vulnerable Environment**

A vulnerability testbed for validating web application security scanners. HIVE provides a comprehensive collection of intentionally vulnerable endpoints across multiple vulnerability categories, along with "false positive" (safe) variants for testing scanner accuracy.

## Table of Contents

- [Quick Start](#quick-start)
- [Using Docker](#using-docker)
- [Vulnerability Categories](#vulnerability-categories)
- [Vulnerability Reference](#vulnerability-reference)
  - [Injection](#injection) (SQLi, Command, SSTI, XXE, LDAP, XPath)
  - [Cross-Site Scripting (XSS)](#cross-site-scripting-xss) (Reflected, Stored, DOM)
  - [File Handling](#file-handling) (Path Traversal, Upload, Source Disclosure)
  - [Authentication & Session](#authentication--session) (Auth Bypass, CSRF, Cookie Flags)
  - [Information Disclosure](#information-disclosure) (Errors, Versions, PII)
  - [Configuration](#configuration) (CORS, CSP, Clickjacking, Headers)
  - [SSRF](#ssrf-server-side-request-forgery)
  - [Open Redirect](#open-redirect)
  - [Serialization](#serialization)
  - [Admin Interfaces & Enumeration](#admin-interfaces--enumeration)
  - [Authentication Mechanisms](#authentication-mechanisms) (JWT, OAuth, Basic, Form)
  - [Form Hijacking](#form-hijacking)
  - [Sensitive Files](#sensitive-files)
  - [HTTP Methods](#http-methods)
  - [Legacy Technologies](#legacy-technologies)
  - [Disclosure](#disclosure)
- [Authentication Types](#authentication-types)
- [Adding New Test Cases](#adding-new-test-cases)
- [API Endpoints](#api-endpoints)
- [Architecture](#architecture)
- [Environment Variables](#environment-variables)
- [Testing Scanner Accuracy](#testing-scanner-accuracy)
- [License](#license)

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

## Vulnerability Reference

Detailed documentation for each vulnerability group, including what it tests, endpoint paths, and vulnerable code patterns.

---

### Injection

**Path:** `/vulns/injection/`
**Tests for:** Server-side injection flaws where user input is incorporated into queries, commands, or templates without proper sanitization.

#### SQL Injection

Covers four database engines (MySQL, PostgreSQL, MSSQL, SQLite) with multiple injection techniques.

| Endpoint | Technique |
|----------|-----------|
| `/vulns/injection/sqli/{db}/error-based` | Error-based extraction via string concatenation |
| `/vulns/injection/sqli/{db}/union-based` | UNION SELECT to retrieve data from other tables |
| `/vulns/injection/sqli/{db}/blind-boolean` | Boolean-based blind inference |
| `/vulns/injection/sqli/{db}/blind-time` | Time-based blind using SLEEP/pg_sleep |
| `/vulns/injection/sqli/{db}/fp/parameterized` | **Safe:** parameterized queries |

Where `{db}` is one of: `mysql`, `postgres`, `mssql`, `sqlite`.

**Vulnerable snippet:**
```go
// String concatenation - VULNERABLE
query := "SELECT id, username, email FROM users WHERE id = " + id
rows, err := db.MySQL.Query(query)
```

**Safe snippet:**
```go
// Parameterized query - SAFE
rows, err := db.MySQL.Query("SELECT id, username, email FROM users WHERE id = ?", id)
```

#### Command Injection

| Endpoint | Technique |
|----------|-----------|
| `/vulns/injection/command/basic` | Shell command with concatenated user input |
| `/vulns/injection/command/blind` | Blind command injection (no output returned) |
| `/vulns/injection/command/fp/sanitized` | **Safe:** input restricted to alphanumeric, dots, hyphens |

**Vulnerable snippet:**
```go
// Shell execution with concatenation - VULNERABLE
cmd := exec.Command("sh", "-c", "ping -c 1 "+host) // host: "localhost; id"
```

**Safe snippet:**
```go
// Direct execution without shell - SAFE
re := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
if !re.MatchString(host) { return }
cmd := exec.Command("ping", "-c", "1", host)
```

#### Server-Side Template Injection (SSTI)

| Endpoint | Technique |
|----------|-----------|
| `/vulns/injection/ssti/go-text` | Go `text/template` with user input in template string |
| `/vulns/injection/ssti/go-html` | Go `html/template` (HTML-escaped but template directives execute) |
| `/vulns/injection/ssti/jinja2` | Simulated Jinja2 (`{{7*7}}` evaluates to `49`) |
| `/vulns/injection/ssti/erb` | Simulated ERB (`<%=7*7%>` evaluates to `49`) |
| `/vulns/injection/ssti/fp/escaped` | **Safe:** input passed as template data, not template code |

**Vulnerable snippet:**
```go
// User input in template string - VULNERABLE
templateStr := fmt.Sprintf("Hello, %s!", name) // name: "{{.}}"
tmpl, _ := texttemplate.New("test").Parse(templateStr)
tmpl.Execute(&buf, nil)
```

**Safe snippet:**
```go
// Input as data only - SAFE
tmpl := htmltemplate.Must(htmltemplate.New("safe").Parse(`Hello, {{.Name}}!`))
tmpl.Execute(&buf, map[string]string{"Name": name})
```

#### XXE (XML External Entity)

| Endpoint | Technique |
|----------|-----------|
| `/vulns/injection/xxe/basic` | XML parsing with external entity resolution |
| `/vulns/injection/xxe/blind` | Blind XXE (exfiltration via out-of-band HTTP) |
| `/vulns/injection/xxe/upload` | XXE via XML file upload |
| `/vulns/injection/xxe/fp/disabled` | **Safe:** rejects `<!DOCTYPE` and `<!ENTITY` |

**Vulnerable payload:**
```xml
<!DOCTYPE user [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>
```

#### LDAP Injection

| Endpoint | Technique |
|----------|-----------|
| `/vulns/injection/ldap/basic` | Filter injection via `(uid=%s)` |
| `/vulns/injection/ldap/auth` | Authentication bypass via `(uid=%s)(userPassword=%s)` |
| `/vulns/injection/ldap/search` | Search filter injection |
| `/vulns/injection/ldap/blind` | Blind LDAP injection |
| `/vulns/injection/ldap/fp/escaped` | **Safe:** rejects `*`, `(`, `)`, `\|`, null bytes |

**Vulnerable snippet:**
```go
// Direct interpolation - VULNERABLE
filter := fmt.Sprintf("(&(uid=%s)(objectClass=person))", username) // username: "admin)(|(uid=*"
```

#### XPath Injection

| Endpoint | Technique |
|----------|-----------|
| `/vulns/injection/xpath/basic` | XPath query injection via `//users/user[username='%s']` |
| `/vulns/injection/xpath/auth` | Authentication bypass via combined username/password query |
| `/vulns/injection/xpath/blind` | Blind XPath injection |
| `/vulns/injection/xpath/fp/parameterized` | **Safe:** alphanumeric-only validation |

**Vulnerable snippet:**
```go
// String interpolation in XPath - VULNERABLE
query := fmt.Sprintf("//users/user[username='%s']", username) // username: "' or '1'='1"
```

#### Other Injection Types

| Endpoint | Tests For |
|----------|-----------|
| `/vulns/injection/css/` | CSS injection via user-controlled style values |
| `/vulns/injection/hpp/` | HTTP Parameter Pollution |
| `/vulns/injection/ssi/` | Server-Side Includes injection |
| `/vulns/injection/ssjs/` | Server-Side JavaScript injection |

---

### Cross-Site Scripting (XSS)

**Path:** `/vulns/xss/`
**Tests for:** Client-side code injection where attacker-controlled input is rendered in the browser without proper encoding.

#### Reflected XSS

| Endpoint | Context |
|----------|---------|
| `/vulns/xss/reflected/html-body` | User input reflected in HTML body without escaping |
| `/vulns/xss/reflected/attribute` | User input in HTML attribute context |
| `/vulns/xss/reflected/javascript` | User input in JavaScript string context |
| `/vulns/xss/reflected/fp/escaped` | **Safe:** uses `html.EscapeString()` |

**Vulnerable snippet:**
```go
// Unescaped output via template.HTML - VULNERABLE
name := r.URL.Query().Get("name")
templates.Render(w, "xss/reflected/html-body", templates.Page{
    FormValue: html.EscapeString(name),
    OutputRaw: template.HTML(name), // Bypasses template escaping
})
```

#### Stored XSS

| Endpoint | Context |
|----------|---------|
| `/vulns/xss/stored/comment` | Stored comments rendered without escaping |
| `/vulns/xss/stored/fp/escaped` | **Safe:** comments escaped with `html.EscapeString()` |

**Vulnerable snippet:**
```go
// Raw output of stored content - VULNERABLE
fmt.Fprintf(w, `<div class="comment">%s</div>`, c) // c: "<script>alert('xss')</script>"
```

#### DOM-based XSS

| Endpoint | Sink |
|----------|------|
| `/vulns/xss/dom/innerhtml` | `innerHTML = location.hash` |
| `/vulns/xss/dom/document-write` | `document.write()` with URL parameter |
| `/vulns/xss/dom/location` | `window.location = params.url` (enables `javascript:` URIs) |
| `/vulns/xss/dom/fp/safe` | **Safe:** uses `textContent` instead of `innerHTML` |

**Vulnerable snippet:**
```javascript
// DOM sink with user-controlled source - VULNERABLE
document.getElementById('output').innerHTML = location.hash;
// Payload: #<img src=x onerror=alert(1)>
```

#### Additional XSS Categories

| Endpoint | Tests For |
|----------|-----------|
| `/vulns/xss/blacklist/` | Blacklist filter bypasses |
| `/vulns/xss/context/` | Context-specific XSS payloads |
| `/vulns/xss/headers/` | XSS via HTTP response headers |

---

### File Handling

**Path:** `/vulns/file/`
**Tests for:** Unsafe file operations including path traversal, unrestricted uploads, and source code exposure.

#### Path Traversal

| Endpoint | Method |
|----------|--------|
| `/vulns/file/pathtraversal/get` | GET parameter: `?file=../../../etc/passwd` |
| `/vulns/file/pathtraversal/post` | POST parameter: `file=../../../etc/passwd` |
| `/vulns/file/pathtraversal/fp/sanitized` | **Safe:** `filepath.Base()` + `filepath.Join()` |

**Vulnerable snippet:**
```go
// Direct file read from user input - VULNERABLE
filename := r.URL.Query().Get("file")
content, err := os.ReadFile(filename)
```

**Safe snippet:**
```go
// Path sanitization - SAFE
basePath := "./static/test"
cleanName := filepath.Base(filename)
cleanName = strings.ReplaceAll(cleanName, "..", "")
safePath := filepath.Join(basePath, cleanName)
content, err := os.ReadFile(safePath)
```

#### File Upload

| Endpoint | Technique |
|----------|-----------|
| `/vulns/file/upload/unrestricted` | No file type validation |
| `/vulns/file/upload/fp/validated` | **Safe:** extension whitelist (.txt, .pdf, .png, .jpg) |

**Vulnerable snippet:**
```go
// No validation on uploaded file - VULNERABLE
file, header, _ := r.FormFile("file")
dest, _ := os.Create(header.Filename)
io.Copy(dest, file)
```

**Safe snippet:**
```go
// Extension whitelist - SAFE
ext := strings.ToLower(filepath.Ext(header.Filename))
allowedExts := map[string]bool{".txt": true, ".pdf": true, ".png": true, ".jpg": true}
if !allowedExts[ext] { http.Error(w, "File type not allowed", 400); return }
```

#### Source Code Disclosure

| Endpoint | Tests For |
|----------|-----------|
| `/vulns/file/sourcedisclosure/` | Exposure of `.git`, `.env`, and backup files |

---

### Authentication & Session

**Path:** `/vulns/auth-session/`
**Tests for:** Weaknesses in authentication mechanisms, session management, and access control.

#### Authentication Bypass

| Endpoint | Technique |
|----------|-----------|
| `/vulns/auth-session/auth-bypass/403-bypass` | Path manipulation to bypass access controls |
| `/vulns/auth-session/auth-bypass/header-abuse` | Trusts `X-Forwarded-For` for IP-based access |
| `/vulns/auth-session/auth-bypass/x-real-ip` | Trusts `X-Real-IP` header |
| `/vulns/auth-session/auth-bypass/x-client-ip` | Trusts `X-Client-IP` header |
| `/vulns/auth-session/auth-bypass/x-true-ip` | Trusts `X-True-IP` header |
| `/vulns/auth-session/auth-bypass/x-forwarded-by` | Trusts `X-Forwarded-By` header |
| `/vulns/auth-session/auth-bypass/x-custom-ip` | Trusts `X-Custom-IP-Authorization` header |
| `/vulns/auth-session/auth-bypass/client-ip` | Trusts `Client-IP` header |
| `/vulns/auth-session/auth-bypass/forwarded` | Trusts RFC 7239 `Forwarded` header |
| `/vulns/auth-session/auth-bypass/referer` | `Referer` header bypass |
| `/vulns/auth-session/auth-bypass/fp/proper-check` | **Safe:** Bearer token validation |
| `/vulns/auth-session/auth-bypass/fp/validated-headers` | **Safe:** uses `RemoteAddr`, ignores client headers |

**Vulnerable snippet:**
```go
// Trusts client-supplied header for access control - VULNERABLE
ip := r.Header.Get("X-Real-IP")
if ip == "127.0.0.1" {
    accessGranted = true
}
```

**Safe snippet:**
```go
// Uses actual connection address - SAFE
remoteAddr := r.RemoteAddr
```

#### CSRF (Cross-Site Request Forgery)

| Endpoint | Technique |
|----------|-----------|
| `/vulns/auth-session/csrf/vulnerable` | Form submission without CSRF token |
| `/vulns/auth-session/csrf/fp/with-token` | **Safe:** CSRF token validation |

**Vulnerable snippet:**
```go
// No token verification - VULNERABLE
if r.Method == http.MethodPost {
    email := r.FormValue("email")
    // Processes form without verifying origin
}
```

**Safe snippet:**
```go
// Token validation - SAFE
token := r.FormValue("csrf_token")
if !tokens[token] {
    http.Error(w, "Invalid CSRF token", 403)
    return
}
delete(tokens, token) // Single-use token
```

#### Other Auth/Session Issues

| Endpoint | Tests For |
|----------|-----------|
| `/vulns/auth-session/cookieflags/` | Missing HttpOnly, Secure, or SameSite cookie flags |
| `/vulns/auth-session/passwordexposure/` | Passwords visible in responses |
| `/vulns/auth-session/sessioninurl/` | Session tokens passed in URL parameters |

---

### Information Disclosure

**Path:** `/vulns/info-disclosure/`
**Tests for:** Unintentional exposure of sensitive information through error messages, headers, comments, or data fields.

#### Error Messages

| Endpoint | Technique |
|----------|-----------|
| `/vulns/info-disclosure/error-messages/database` | Full SQL error with query string exposed |
| `/vulns/info-disclosure/error-messages/stack-trace` | Full stack trace with file paths and framework versions |
| `/vulns/info-disclosure/error-messages/fp/generic` | **Safe:** generic error message only |

**Vulnerable snippet:**
```go
// Detailed error exposed to user - VULNERABLE
fmt.Fprintf(w, "Database Error: %v\nQuery: %s", err, query)
```

#### Version Disclosure

| Endpoint | Technique |
|----------|-----------|
| `/vulns/info-disclosure/version-disclosure/server-headers` | `Server: Apache/2.4.51`, `X-Powered-By: PHP/7.4.3` |
| `/vulns/info-disclosure/version-disclosure/comments` | `<!-- Generated by WordPress 5.8.1 -->` in HTML source |
| `/vulns/info-disclosure/version-disclosure/fp/hidden` | **Safe:** no version information exposed |

#### PII Exposure

| Endpoint | Data Type |
|----------|-----------|
| `/vulns/info-disclosure/pii/emails` | Full email addresses in table data |
| `/vulns/info-disclosure/pii/emails-in-html` | Emails in HTML comments and hidden fields |
| `/vulns/info-disclosure/pii/emails-in-js` | Emails in JavaScript variables |
| `/vulns/info-disclosure/pii/credit-cards` | Full credit card numbers |
| `/vulns/info-disclosure/pii/ssn` | Full Social Security Numbers |
| `/vulns/info-disclosure/pii/phone-numbers` | Full phone numbers |
| `/vulns/info-disclosure/pii/fp/redacted` | **Safe:** all PII properly masked |

---

### Configuration

**Path:** `/vulns/config/`
**Tests for:** Security misconfigurations in HTTP headers, CORS policies, content security policies, and other server-side settings.

#### CORS (Cross-Origin Resource Sharing)

| Endpoint | Misconfiguration |
|----------|-----------------|
| `/vulns/config/cors/permissive` | `Access-Control-Allow-Origin: *` with credentials |
| `/vulns/config/cors/reflect-origin` | Reflects any `Origin` header without validation |
| `/vulns/config/cors/fp/restricted` | **Safe:** whitelist-based origin validation |

**Vulnerable snippet:**
```go
// Reflects any origin - VULNERABLE
origin := r.Header.Get("Origin")
w.Header().Set("Access-Control-Allow-Origin", origin)
w.Header().Set("Access-Control-Allow-Credentials", "true")
```

**Safe snippet:**
```go
// Whitelist validation - SAFE
allowed := map[string]bool{"https://trusted.example.com": true}
origin := r.Header.Get("Origin")
if allowed[origin] {
    w.Header().Set("Access-Control-Allow-Origin", origin)
}
```

#### CSP (Content Security Policy)

| Endpoint | Misconfiguration |
|----------|-----------------|
| `/vulns/config/csp/missing` | No CSP header set |
| `/vulns/config/csp/unsafe-inline` | `default-src 'self' 'unsafe-inline' 'unsafe-eval'` |
| `/vulns/config/csp/fp/strict` | **Safe:** strict CSP with `default-src 'self'; script-src 'self'` |

#### Clickjacking

| Endpoint | Misconfiguration |
|----------|-----------------|
| `/vulns/config/clickjacking/no-protection` | No `X-Frame-Options` header |
| `/vulns/config/clickjacking/fp/x-frame-options` | **Safe:** `X-Frame-Options: DENY` + `frame-ancestors 'none'` |

#### Security Headers

| Endpoint | Issue |
|----------|-------|
| `/vulns/config/headers/xss-filter-disabled` | `X-XSS-Protection: 0` |
| `/vulns/config/headers/xss-filter-enabled` | `X-XSS-Protection: 1` (without `mode=block`) |
| `/vulns/config/headers/xff-bypass` | Trusts `X-Forwarded-For` for access control |
| `/vulns/config/headers/client-ip-bypass` | Trusts `X-Real-IP`, `X-Client-IP`, `X-Originating-IP` |
| `/vulns/config/headers/multiple-content-types` | Multiple `Content-Type` headers (parsing confusion) |
| `/vulns/config/headers/url-override` | Trusts `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Path` |
| `/vulns/config/headers/url-override-legacy` | Trusts `Redirect`, `X-Host`, `X-HTTP-DestinationURL` |
| `/vulns/config/headers/fp/xss-filter-block` | **Safe:** `X-XSS-Protection: 1; mode=block` |
| `/vulns/config/headers/fp/xff-validated` | **Safe:** uses `RemoteAddr` only |
| `/vulns/config/headers/fp/single-content-type` | **Safe:** single `Content-Type` header |
| `/vulns/config/headers/fp/url-override-ignored` | **Safe:** ignores override headers |

#### Other Configuration Issues

| Endpoint | Tests For |
|----------|-----------|
| `/vulns/config/contenttype/` | Content-Type validation and MIME mismatches |
| `/vulns/config/hostheader/` | Host header injection |
| `/vulns/config/httpmethods/` | Unintended HTTP methods (PUT, DELETE, TRACE) |
| `/vulns/config/openredirect/` | Open redirect via configuration |

---

### SSRF (Server-Side Request Forgery)

**Path:** `/vulns/ssrf/`
**Tests for:** Server-side request forgery where the application makes HTTP requests or DNS lookups to attacker-controlled destinations.

| Endpoint | Technique |
|----------|-----------|
| `/vulns/ssrf/http` | Unrestricted `http.Get(url)` with user-supplied URL |
| `/vulns/ssrf/dns` | Unrestricted `net.LookupIP(hostname)` |
| `/vulns/ssrf/oob-http` | Out-of-band SSRF via HTTP callback |
| `/vulns/ssrf/oob-dns` | Out-of-band SSRF via DNS lookup |
| `/vulns/ssrf/oob-image` | Out-of-band SSRF via image loading |
| `/vulns/ssrf/fp/validated` | **Safe:** blocks private IPs, localhost, metadata endpoints; HTTPS only |

**Vulnerable snippet:**
```go
// No URL validation - VULNERABLE
targetURL := r.URL.Query().Get("url")
resp, err := http.Get(targetURL) // Attacker can reach internal services
```

**Safe snippet:**
```go
// Blocklist + scheme validation - SAFE
blocked := []string{"localhost", "127.0.0.1", "169.254.", "10.", "192.168.", "172."}
for _, b := range blocked {
    if strings.Contains(targetURL, b) { http.Error(w, "Blocked", 403); return }
}
if !strings.HasPrefix(targetURL, "https://") { http.Error(w, "HTTPS only", 403); return }
```

---

### Open Redirect

**Path:** `/vulns/redirect/`
**Tests for:** Unvalidated redirects that can send users to attacker-controlled sites for phishing or credential theft.

| Endpoint | Technique |
|----------|-----------|
| `/vulns/redirect/basic` | `http.Redirect()` with user-supplied URL |
| `/vulns/redirect/meta` | `<meta http-equiv="refresh">` with user URL |
| `/vulns/redirect/javascript` | `window.location` set from parameter |
| `/vulns/redirect/parameter` | Redirect via `?next=` parameter |
| `/vulns/redirect/double-encode` | Single URL decode allows double-encoded bypass |
| `/vulns/redirect/fp/whitelist` | **Safe:** whitelist of allowed paths |
| `/vulns/redirect/fp/domain` | **Safe:** domain validation (localhost only) |

**Vulnerable snippet:**
```go
// Unvalidated redirect - VULNERABLE
target := r.URL.Query().Get("url")
http.Redirect(w, r, target, http.StatusFound) // target: "https://evil.com"
```

---

### Serialization

**Path:** `/vulns/serialization/`
**Tests for:** Insecure deserialization where untrusted data is unmarshalled without type constraints, allowing unexpected object structures.

| Endpoint | Technique |
|----------|-----------|
| `/vulns/serialization/json` | `json.Unmarshal()` into `interface{}` (accepts any structure) |
| `/vulns/serialization/xml` | XML deserialization |
| `/vulns/serialization/fp/safe` | **Safe:** deserialize into strict struct with `DisallowUnknownFields()` |

**Vulnerable snippet:**
```go
// Accepts arbitrary JSON structure - VULNERABLE
var data interface{}
decoder := json.NewDecoder(r.Body)
decoder.Decode(&data)
```

**Safe snippet:**
```go
// Strict struct with field validation - SAFE
var data SafeStruct
decoder := json.NewDecoder(r.Body)
decoder.DisallowUnknownFields()
decoder.Decode(&data)
```

---

### Admin Interfaces & Enumeration

**Path:** `/vulns/admin/`
**Tests for:** Exposed administrative interfaces, debug endpoints, and user enumeration vectors.

| Endpoint | What It Exposes |
|----------|----------------|
| `/vulns/admin/login` | Generic admin login page |
| `/vulns/admin/dashboard` | Admin dashboard |
| `/vulns/admin/console` | Admin console |
| `/vulns/admin/wp-admin` | WordPress admin panel |
| `/vulns/admin/wp-login` | WordPress login page |
| `/vulns/admin/phpmyadmin` | phpMyAdmin interface |
| `/vulns/admin/actuator` | Spring Boot Actuator |
| `/vulns/admin/actuator/env` | Environment variables (DB_PASSWORD, API_SECRET, AWS creds) |
| `/vulns/admin/actuator/health` | Spring health check |
| `/vulns/admin/laravel-debugbar` | Laravel debug bar (session data, DB queries) |
| `/vulns/admin/fp/protected` | **Safe:** protected with HTTP Basic Auth |

#### WordPress User Enumeration

| Endpoint | Technique |
|----------|-----------|
| `/vulns/admin/wp-user-enum/author` | Author parameter enumeration via redirect |
| `/vulns/admin/wp-user-enum/api` | REST API user listing (`/wp-json/wp/v2/users`) |
| `/vulns/admin/wp-user-enum/fp/blocked` | **Safe:** protected endpoint |

---

### Authentication Mechanisms

**Path:** `/vulns/auth/`
**Tests for:** Various authentication implementations and their specific weaknesses. These endpoints also serve as login targets when `AUTH_TYPE` is configured.

#### JWT Vulnerabilities

| Endpoint | Vulnerability |
|----------|--------------|
| `/vulns/auth/jwt/none-alg` | Accepts tokens with `"alg": "none"` (no signature) |
| `/vulns/auth/jwt/weak-secret` | HMAC signed with weak secret `"secret"` |
| `/vulns/auth/jwt/no-expiry` | Does not validate token expiration |
| `/vulns/auth/jwt/url-param` | JWT passed in URL parameter (leaks via Referer header) |
| `/vulns/auth/jwt/fp/validated` | **Safe:** HS256 only, expiry check, signature validation |

**Vulnerable snippet:**
```go
// Accepts "none" algorithm - VULNERABLE
if strings.ToLower(header.Alg) == "none" {
    fmt.Fprintf(w, "Token accepted (none algorithm)!")
}
```

#### Other Auth Mechanisms

| Endpoint Group | Technique |
|----------------|-----------|
| `/vulns/auth/ajax-json/` | AJAX/JSON login with cookie session, no CSRF |
| `/vulns/auth/form-post/` | Traditional form login with weak credentials |
| `/vulns/auth/http-basic/` | HTTP Basic with credentials in Authorization header |
| `/vulns/auth/multi-step/` | Multi-step auth with unencrypted step cookies |
| `/vulns/auth/oauth/` | Simplified OAuth without PKCE |

---

### Form Hijacking

**Path:** `/vulns/formhijack/`
**Tests for:** Form action manipulation, hidden field tampering, and link manipulation that can redirect form submissions to attacker-controlled endpoints.

---

### Sensitive Files

**Path:** `/vulns/files/`
**Tests for:** Exposure of sensitive files that should not be publicly accessible, including backups, version control data, environment files, and debug pages.

---

### HTTP Methods

**Path:** `/vulns/methods/`
**Tests for:** Dangerous HTTP methods (PUT, TRACE, DELETE, OPTIONS) that are enabled but should be restricted.

---

### Legacy Technologies

**Path:** `/vulns/legacy/`
**Tests for:** Vulnerabilities in legacy/deprecated technologies including Flash, Silverlight, ASP.NET ViewState, and older server-side frameworks (Perl, Ruby, Python).

---

### Disclosure

**Path:** `/vulns/disclosure/`
**Tests for:** Sensitive data exposure in responses, including private IP addresses, private keys, JWT secrets, database connection strings, and directory listings.

---

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

```
Copyright © 2025 subzerodev
This work is free. You can redistribute it and/or modify it under the
terms of the Do What The Fuck You Want To Public License, Version 2,
as published by Sam Hocevar. See the COPYING file for more details.
```

This software is provided for authorized security testing and educational purposes only.
