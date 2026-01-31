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
