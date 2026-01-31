package serialization

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/serialization/json", jsonDeserialize)
		handlers.Handle("/vulns/serialization/xml", xmlDeserialize)
		handlers.Handle("/vulns/serialization/fp/safe", fpSafe)
	})
}

func jsonDeserialize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		// VULNERABLE: Deserializes arbitrary JSON into interface{}
		if err := decoder.Decode(&data); err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="/static/css/hive.css"></head><body><div class="container"><h1>Error</h1><pre>%v</pre></div></body></html>`, err)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JSON Deserialized</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>JSON Deserialized</h1>
<pre>%+v</pre>
<p><small>VULNERABLE: Arbitrary JSON deserialized to map[string]interface{}</small></p>
<a href="/vulns/serialization/json">Back</a>
</div>
</body></html>`, data)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JSON Deserialization</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>JSON Deserialization</h1>
<form method="POST">
    <textarea name="json" rows="5" cols="50">{"__type": "malicious", "cmd": "id"}</textarea><br>
    <button type="submit">Deserialize</button>
</form>
<p><small>VULNERABLE: Accepts arbitrary JSON structure</small></p>
</div>
</body></html>`)
}

func xmlDeserialize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var data struct {
			XMLName xml.Name
			Content string `xml:",innerxml"`
		}
		decoder := xml.NewDecoder(r.Body)
		// Note: Go's xml package is safe from XXE by default
		// This demonstrates the endpoint pattern
		if err := decoder.Decode(&data); err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="/static/css/hive.css"></head><body><div class="container"><h1>Error</h1><pre>%v</pre></div></body></html>`, err)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XML Deserialized</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XML Deserialized</h1>
<p>Element: %s</p>
<pre>%s</pre>
<a href="/vulns/serialization/xml">Back</a>
</div>
</body></html>`, data.XMLName.Local, data.Content)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XML Deserialization</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>XML Deserialization</h1>
<form method="POST">
    <textarea name="xml" rows="5" cols="50">&lt;root&gt;&lt;data&gt;test&lt;/data&gt;&lt;/root&gt;</textarea><br>
    <button type="submit">Deserialize</button>
</form>
<p><small>Note: Go's xml package is XXE-safe by default</small></p>
</div>
</body></html>`)
}

func fpSafe(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// SAFE: Deserialize into strict struct
		var data struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&data); err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="/static/css/hive.css"></head><body><div class="container"><h1>Error</h1><pre>%v</pre><a href="/vulns/serialization/fp/safe">Back</a></div></body></html>`, err)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Safe Deserialization</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Safe Deserialization</h1>
<p>Name: %s</p>
<p>Email: %s</p>
<p><small>SAFE: Strict struct with DisallowUnknownFields</small></p>
<a href="/vulns/serialization/fp/safe">Back</a>
</div>
</body></html>`, data.Name, data.Email)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Safe Deserialization</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Safe Deserialization</h1>
<form method="POST">
    <textarea name="json" rows="5" cols="50">{"name": "John", "email": "john@example.com"}</textarea><br>
    <button type="submit">Deserialize</button>
</form>
<p><small>SAFE: Only accepts known fields in strict struct</small></p>
</div>
</body></html>`)
}
