package blacklist

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Blacklist filter levels (progressively stricter)
		handlers.Handle("/vulns/xss/blacklist/level1", level1)
		handlers.Handle("/vulns/xss/blacklist/level2", level2)
		handlers.Handle("/vulns/xss/blacklist/level3", level3)
		handlers.Handle("/vulns/xss/blacklist/level4", level4)
		handlers.Handle("/vulns/xss/blacklist/level5", level5)
		handlers.Handle("/vulns/xss/blacklist/level6", level6)
		handlers.Handle("/vulns/xss/blacklist/level7", level7)

		// FP - Properly escaped (whitelist approach)
		handlers.Handle("/vulns/xss/blacklist/fp/whitelist", fpWhitelist)
	})
}

func renderPage(w http.ResponseWriter, title, input, hint, filterDesc, filtered string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Blacklist - %s</title></head>
<body>
<h1>XSS Blacklist Filter - %s</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Enter text" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">%s</div>
<h3>Filter:</h3>
<p><small>%s</small></p>
<h3>Bypass hint:</h3>
<p><small>%s</small></p>
<p><a href="/vulns/xss/blacklist/">Back to Blacklist Tests</a></p>
</body></html>`, title, title, html.EscapeString(input), filtered, filterDesc, hint)
}

// Level 1: Blocks exact string "<script>"
// Bypass: Use uppercase, mixed case, or other tags
func level1(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Only blocks exact lowercase "<script>"
	filtered := strings.ReplaceAll(input, "<script>", "")
	filtered = strings.ReplaceAll(filtered, "</script>", "")

	renderPage(w, "Level 1", input,
		"Try: &lt;SCRIPT&gt;alert(1)&lt;/SCRIPT&gt; or &lt;img src=x onerror=alert(1)&gt;",
		"Blocks: &lt;script&gt; and &lt;/script&gt; (exact match, case-sensitive)",
		filtered)
}

// Level 2: Blocks "<script>" case-insensitive
// Bypass: Use other tags like <img>, <svg>, <body>
func level2(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Blocks script tags but not other XSS vectors
	re := regexp.MustCompile(`(?i)</?script[^>]*>`)
	filtered := re.ReplaceAllString(input, "")

	renderPage(w, "Level 2", input,
		"Try: &lt;img src=x onerror=alert(1)&gt; or &lt;svg onload=alert(1)&gt;",
		"Blocks: &lt;script&gt; tags (case-insensitive)",
		filtered)
}

// Level 3: Blocks <script> and <img>
// Bypass: Use <svg>, <body>, <input>, <iframe>
func level3(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Blocks some tags but misses others
	re := regexp.MustCompile(`(?i)</?script[^>]*>|<img[^>]*>`)
	filtered := re.ReplaceAllString(input, "")

	renderPage(w, "Level 3", input,
		"Try: &lt;svg onload=alert(1)&gt; or &lt;body onload=alert(1)&gt; or &lt;input onfocus=alert(1) autofocus&gt;",
		"Blocks: &lt;script&gt; and &lt;img&gt; tags",
		filtered)
}

// Level 4: Blocks <script>, <img>, <svg>, <body>
// Bypass: Use <iframe>, <input>, <details>, <marquee>, event handlers in existing tags
func level4(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Still missing many XSS vectors
	re := regexp.MustCompile(`(?i)</?script[^>]*>|<img[^>]*>|<svg[^>]*>|<body[^>]*>`)
	filtered := re.ReplaceAllString(input, "")

	renderPage(w, "Level 4", input,
		"Try: &lt;iframe src=javascript:alert(1)&gt; or &lt;input onfocus=alert(1) autofocus&gt; or &lt;details open ontoggle=alert(1)&gt;",
		"Blocks: &lt;script&gt;, &lt;img&gt;, &lt;svg&gt;, &lt;body&gt; tags",
		filtered)
}

// Level 5: Blocks common XSS tags and "javascript:"
// Bypass: Use data: URLs, encoded payloads, or less common event handlers
func level5(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Blocks common vectors but misses encoded/obfuscated ones
	re := regexp.MustCompile(`(?i)</?script[^>]*>|<img[^>]*>|<svg[^>]*>|<body[^>]*>|<iframe[^>]*>|javascript:`)
	filtered := re.ReplaceAllString(input, "")

	renderPage(w, "Level 5", input,
		"Try: &lt;input onfocus=alert(1) autofocus&gt; or &lt;a href=javas&#99;ript:alert(1)&gt;click&lt;/a&gt; or &lt;details open ontoggle=alert(1)&gt;",
		"Blocks: Common XSS tags and javascript: URLs",
		filtered)
}

// Level 6: Blocks common event handlers
// Bypass: Use less common handlers like onpointerover, onanimationend, ontransitionend
func level6(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Blocks common handlers but misses newer/obscure ones
	re := regexp.MustCompile(`(?i)</?script[^>]*>|<img[^>]*>|<svg[^>]*>|javascript:|onerror|onload|onclick|onfocus|onmouseover`)
	filtered := re.ReplaceAllString(input, "")

	renderPage(w, "Level 6", input,
		"Try: &lt;div onpointerover=alert(1)&gt;hover&lt;/div&gt; or &lt;marquee onstart=alert(1)&gt; or &lt;video&gt;&lt;source onerror=alert(1)&gt;",
		"Blocks: Common XSS tags and event handlers (onerror, onload, onclick, onfocus, onmouseover)",
		filtered)
}

// Level 7: Blocks "alert" function
// Bypass: Use other functions like confirm(), prompt(), eval(), or constructor
func level7(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// VULNERABLE: Blocks alert but misses other execution methods
	re := regexp.MustCompile(`(?i)</?script[^>]*>|javascript:|alert`)
	filtered := re.ReplaceAllString(input, "")

	renderPage(w, "Level 7", input,
		"Try: &lt;img src=x onerror=confirm(1)&gt; or &lt;img src=x onerror=eval('ale'+'rt(1)')&gt; or &lt;img src=x onerror=[].constructor.constructor('return this')().alert(1)&gt;",
		"Blocks: &lt;script&gt; tags, javascript: URLs, and 'alert'",
		filtered)
}

// FP - Whitelist approach (safe)
func fpWhitelist(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if input == "" {
		input = "test"
	}

	// SAFE: Whitelist approach - only allow alphanumeric and basic punctuation
	re := regexp.MustCompile(`[^a-zA-Z0-9\s.,!?-]`)
	filtered := re.ReplaceAllString(input, "")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>XSS Blacklist - Safe (Whitelist)</title></head>
<body>
<h1>XSS Filter - Safe (Whitelist Approach)</h1>
<form method="GET">
    <input name="q" value="%s" placeholder="Enter text" style="width:300px">
    <button type="submit">Submit</button>
</form>
<h2>Output:</h2>
<div id="output">%s</div>
<h3>Filter:</h3>
<p><small>SAFE: Whitelist approach - only allows alphanumeric characters, spaces, and basic punctuation (.,!?-)</small></p>
<p><a href="/vulns/xss/blacklist/">Back to Blacklist Tests</a></p>
</body></html>`, html.EscapeString(input), html.EscapeString(filtered))
}
