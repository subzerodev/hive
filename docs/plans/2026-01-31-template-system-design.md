# Template System Design

Replace `fmt.Fprintf()` HTML generation with Go's `html/template` package.

## Goals

- Separate HTML from Go code
- Minimal boilerplate per vulnerability page
- Copy-paste friendly patterns for new vulns
- Clear distinction between vulnerable and safe output

## Base Layout

**File: `templates/base.html`**

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

All pages inherit this. Navbar can be added here later.

## Vulnerability Template Pattern

Each vuln page defines only its unique content.

**File: `templates/vulns/xss/reflected/html-body.html`**

```html
{{define "content"}}
<form method="GET">
    <input name="name" value="{{.FormValue}}" placeholder="Your name">
    <button type="submit">Submit</button>
</form>
{{if .Output}}
<p>Welcome, {{.OutputRaw}}!</p>
{{end}}
<p><small>Try: &lt;script&gt;alert(1)&lt;/script&gt;</small></p>
{{end}}
```

- `{{.FormValue}}` - auto-escaped (safe)
- `{{.OutputRaw}}` - unescaped (for vulnerable endpoints)
- False-positive variants use `{{.Output}}` instead

## Template Package

**File: `templates/templates.go`**

```go
package templates

import (
    "html/template"
    "net/http"
    "path/filepath"
)

var baseTemplate *template.Template

func Init() {
    baseTemplate = template.Must(template.ParseFiles("templates/base.html"))
}

func Render(w http.ResponseWriter, name string, data any) {
    tmpl := template.Must(baseTemplate.Clone())
    tmpl = template.Must(tmpl.ParseFiles(
        filepath.Join("templates/vulns", name+".html"),
    ))

    w.Header().Set("Content-Type", "text/html")
    tmpl.Execute(w, data)
}

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

## Handler Pattern

**Before:**
```go
func htmlBody(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if name == "" {
        name = "Guest"
    }
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Reflected XSS - HTML Body</title>
...30 more lines...`, name, html.EscapeString(name))
}
```

**After:**
```go
func htmlBody(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if name == "" {
        name = "Guest"
    }
    templates.Render(w, "xss/reflected/html-body", templates.Page{
        Title:     "Reflected XSS - HTML Body",
        Heading:   "Welcome!",
        FormValue: name,
        OutputRaw: template.HTML(name),
    })
}
```

## Dynamic Output (SQLi example)

**Template: `templates/vulns/injection/sqli/sqlite/error-based.html`**

```html
{{define "content"}}
<form method="GET">
    <input name="id" value="{{.FormValue}}" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>{{if .Error}}Error: {{.ErrorRaw}}{{else}}{{range .Rows}}ID: {{.ID}}, Username: {{.Username}}, Email: {{.Email}}
{{end}}{{end}}</pre>
{{end}}
```

## File Structure

```
templates/
├── base.html
├── templates.go
└── vulns/
    ├── xss/
    │   └── reflected/
    │       ├── html-body.html
    │       ├── attribute.html
    │       └── fp/escaped.html
    ├── injection/
    │   └── sqli/
    │       └── sqlite/
    │           ├── error-based.html
    │           └── fp/parameterized.html
    └── ...
```

## Migration

1. Add `templates/` package with base layout and `Render()` helper
2. Call `templates.Init()` in `main.go`
3. Convert handlers one category at a time
4. Existing handlers continue working during migration

## Not Included

- Template caching/hot-reload (unnecessary for test harness)
- Complex template inheritance (one base layout suffices)
- HTMX (solves different problem - interactivity, not templating)
