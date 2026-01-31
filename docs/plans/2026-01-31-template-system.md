# Template System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace `fmt.Fprintf()` HTML generation with Go's `html/template` for cleaner vuln page authoring.

**Architecture:** Base layout template + per-page content templates. Handlers call `templates.Render()` with a `Page` struct. Existing handlers continue working during incremental migration.

**Tech Stack:** Go `html/template` (stdlib), no external dependencies.

**Worktree:** `/home/subzerodev/workspace/hive/.worktrees/template-system`

---

## Task 1: Create Base Template

**Files:**
- Create: `templates/base.html`

**Step 1: Create templates directory**

```bash
mkdir -p templates
```

**Step 2: Create base.html**

Create `templates/base.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
    <h1>{{.Heading}}</h1>
    {{template "content" .}}
</div>
</body>
</html>
```

**Step 3: Commit**

```bash
git add templates/base.html
git commit -m "feat(templates): add base layout template"
```

---

## Task 2: Create Templates Package

**Files:**
- Create: `templates/templates.go`

**Step 1: Create templates.go**

Create `templates/templates.go`:

```go
package templates

import (
	"html/template"
	"io"
	"path/filepath"
)

var baseTemplate *template.Template

// Init loads the base template. Call once at startup.
func Init() {
	baseTemplate = template.Must(template.ParseFiles("templates/base.html"))
}

// Render executes base + content template with the given data.
func Render(w io.Writer, name string, data any) error {
	tmpl := template.Must(baseTemplate.Clone())
	tmpl = template.Must(tmpl.ParseFiles(
		filepath.Join("templates/vulns", name+".html"),
	))
	return tmpl.Execute(w, data)
}

// Page holds common data for vulnerability pages.
type Page struct {
	Title     string
	Heading   string
	FormValue string
	Output    string        // auto-escaped
	OutputRaw template.HTML // unescaped (for vulns)
	Error     string
	ErrorRaw  template.HTML
	Rows      []any
	Extra     map[string]any
}
```

**Step 2: Verify it compiles**

```bash
go build ./templates
```

Expected: No errors

**Step 3: Commit**

```bash
git add templates/templates.go
git commit -m "feat(templates): add Render helper and Page struct"
```

---

## Task 3: Initialize Templates in main.go

**Files:**
- Modify: `main.go:14` (add import)
- Modify: `main.go:85` (add Init call after db.Init)

**Step 1: Add import**

Add to imports in `main.go`:

```go
"github.com/subzerodev/hive/templates"
```

**Step 2: Add Init call**

After `db.Init()` (around line 85), add:

```go
// Initialize templates
templates.Init()
```

**Step 3: Verify it compiles and runs**

```bash
go build . && ./hive &
curl -s http://localhost:8080/health
pkill hive
```

Expected: `{"status":"healthy"}`

**Step 4: Commit**

```bash
git add main.go
git commit -m "feat(templates): initialize template system at startup"
```

---

## Task 4: Create First Content Template (XSS html-body)

**Files:**
- Create: `templates/vulns/xss/reflected/html-body.html`

**Step 1: Create directory structure**

```bash
mkdir -p templates/vulns/xss/reflected
```

**Step 2: Create html-body.html**

Create `templates/vulns/xss/reflected/html-body.html`:

```html
{{define "content"}}
<form method="GET">
    <input name="name" value="{{.FormValue}}" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<p>Welcome, {{.OutputRaw}}!</p>
<p><small>Try: &lt;script&gt;alert(1)&lt;/script&gt;</small></p>
{{end}}
```

**Step 3: Commit**

```bash
git add templates/vulns/xss/reflected/html-body.html
git commit -m "feat(templates): add xss/reflected/html-body template"
```

---

## Task 5: Convert html-body Handler

**Files:**
- Modify: `vulns/xss/reflected/handlers.go:20-43`

**Step 1: Add import**

Add to imports in `vulns/xss/reflected/handlers.go`:

```go
"html/template"

"github.com/subzerodev/hive/templates"
```

Remove `"fmt"` import (will be unused after conversion).

**Step 2: Replace htmlBody function**

Replace the `htmlBody` function (lines 20-43) with:

```go
func htmlBody(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html")
	templates.Render(w, "xss/reflected/html-body", templates.Page{
		Title:     "Reflected XSS - HTML Body",
		Heading:   "Reflected XSS - HTML Body",
		FormValue: html.EscapeString(name),
		OutputRaw: template.HTML(name), // VULNERABLE: unescaped
	})
}
```

**Step 3: Verify it compiles**

```bash
go build ./vulns/xss/reflected
```

Expected: No errors

**Step 4: Manual test**

```bash
go build . && ./hive &
sleep 1
curl -s "http://localhost:8080/vulns/xss/reflected/html-body?name=Test"
pkill hive
```

Expected: HTML response with "Welcome, Test!" and proper page structure

**Step 5: Commit**

```bash
git add vulns/xss/reflected/handlers.go
git commit -m "feat(xss): convert html-body handler to use templates"
```

---

## Task 6: Create and Convert Remaining XSS Reflected Templates

**Files:**
- Create: `templates/vulns/xss/reflected/attribute.html`
- Create: `templates/vulns/xss/reflected/javascript.html`
- Create: `templates/vulns/xss/reflected/fp/escaped.html`
- Modify: `vulns/xss/reflected/handlers.go`

**Step 1: Create attribute.html**

Create `templates/vulns/xss/reflected/attribute.html`:

```html
{{define "content"}}
<form method="GET">
    <input name="color" value="{{.FormValue}}" placeholder="Color">
    <button type="submit">Change Color</button>
</form>
<h2 style="color: {{.OutputRaw}}">Colored Text</h2>
<p><small>Try: red" onmouseover="alert(1)</small></p>
{{end}}
```

**Step 2: Create javascript.html**

Create `templates/vulns/xss/reflected/javascript.html`:

```html
{{define "content"}}
<form method="GET">
    <input name="msg" value="{{.FormValue}}" placeholder="Message">
    <button type="submit">Show Message</button>
</form>
<script>
var message = "{{.OutputRaw}}";
document.write("<p>" + message + "</p>");
</script>
<p><small>Try: ";alert(1);//</small></p>
{{end}}
```

**Step 3: Create fp/escaped.html**

```bash
mkdir -p templates/vulns/xss/reflected/fp
```

Create `templates/vulns/xss/reflected/fp/escaped.html`:

```html
{{define "content"}}
<form method="GET">
    <input name="name" value="{{.FormValue}}" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
<p>Welcome, {{.Output}}!</p>
<p><small>Input is properly escaped</small></p>
{{end}}
```

**Step 4: Update handlers.go**

Replace the entire `vulns/xss/reflected/handlers.go` with:

```go
package reflected

import (
	"html"
	"html/template"
	"net/http"

	"github.com/subzerodev/hive/handlers"
	"github.com/subzerodev/hive/templates"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/xss/reflected/html-body", htmlBody)
		handlers.Handle("/vulns/xss/reflected/attribute", attribute)
		handlers.Handle("/vulns/xss/reflected/javascript", javascript)
		handlers.Handle("/vulns/xss/reflected/fp/escaped", fpEscaped)
	})
}

func htmlBody(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html")
	templates.Render(w, "xss/reflected/html-body", templates.Page{
		Title:     "Reflected XSS - HTML Body",
		Heading:   "Reflected XSS - HTML Body",
		FormValue: html.EscapeString(name),
		OutputRaw: template.HTML(name),
	})
}

func attribute(w http.ResponseWriter, r *http.Request) {
	color := r.URL.Query().Get("color")
	if color == "" {
		color = "blue"
	}

	w.Header().Set("Content-Type", "text/html")
	templates.Render(w, "xss/reflected/attribute", templates.Page{
		Title:     "Reflected XSS - Attribute",
		Heading:   "Reflected XSS - Attribute",
		FormValue: html.EscapeString(color),
		OutputRaw: template.HTML(color),
	})
}

func javascript(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	if msg == "" {
		msg = "Hello"
	}

	w.Header().Set("Content-Type", "text/html")
	templates.Render(w, "xss/reflected/javascript", templates.Page{
		Title:     "Reflected XSS - JavaScript",
		Heading:   "Reflected XSS - JavaScript",
		FormValue: html.EscapeString(msg),
		OutputRaw: template.HTML(msg),
	})
}

func fpEscaped(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	escaped := html.EscapeString(name)
	w.Header().Set("Content-Type", "text/html")
	templates.Render(w, "xss/reflected/fp/escaped", templates.Page{
		Title:     "Reflected XSS - Safe",
		Heading:   "Reflected XSS - Safe (Escaped)",
		FormValue: escaped,
		Output:    escaped,
	})
}
```

**Step 5: Verify it compiles**

```bash
go build .
```

Expected: No errors

**Step 6: Manual test all endpoints**

```bash
./hive &
sleep 1
curl -s "http://localhost:8080/vulns/xss/reflected/html-body?name=Test" | grep -o "Welcome.*"
curl -s "http://localhost:8080/vulns/xss/reflected/attribute?color=red" | grep -o 'style="color:.*"'
curl -s "http://localhost:8080/vulns/xss/reflected/javascript?msg=Hi" | grep -o 'var message.*'
curl -s "http://localhost:8080/vulns/xss/reflected/fp/escaped?name=Test" | grep -o "Welcome.*"
pkill hive
```

Expected: Each endpoint returns expected content

**Step 7: Commit**

```bash
git add templates/vulns/xss/reflected/ vulns/xss/reflected/handlers.go
git commit -m "feat(xss): convert all reflected XSS handlers to templates"
```

---

## Task 7: Verify Vulnerability Still Works

**Files:** None (verification only)

**Step 1: Test vulnerable endpoint with XSS payload**

```bash
go build . && ./hive &
sleep 1
curl -s "http://localhost:8080/vulns/xss/reflected/html-body?name=<script>alert(1)</script>" | grep -o "<script>alert(1)</script>"
pkill hive
```

Expected: `<script>alert(1)</script>` appears unescaped (vulnerability preserved)

**Step 2: Test safe endpoint rejects XSS**

```bash
go build . && ./hive &
sleep 1
curl -s "http://localhost:8080/vulns/xss/reflected/fp/escaped?name=<script>alert(1)</script>" | grep -o "&lt;script&gt;"
pkill hive
```

Expected: `&lt;script&gt;` (escaped, safe)

---

## Summary

After completing these tasks:
- Template system is in place and initialized
- XSS reflected handlers are fully converted as proof of concept
- Remaining handlers can be migrated incrementally using the same pattern
- Vulnerabilities still work as intended

**Next steps (future work):**
- Convert remaining handler categories one at a time
- Add navbar to base.html once all pages use templates
