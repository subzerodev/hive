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
