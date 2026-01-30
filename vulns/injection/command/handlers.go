// vulns/injection/command/handlers.go
package command

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/command/basic", basic)
		handlers.Handle("/vulns/injection/command/blind", blind)
		handlers.Handle("/vulns/injection/command/fp/sanitized", fpSanitized)
	})
}

func basic(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "localhost"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Command Injection - Basic</title></head>
<body>
<h1>Ping Test</h1>
<form method="GET">
    <input name="host" value="%s" placeholder="Hostname">
    <button type="submit">Ping</button>
</form>
<h2>Results:</h2>
<pre>`, host)

	// VULNERABLE: Direct command injection
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "ping -n 1 "+host)
	} else {
		cmd = exec.Command("sh", "-c", "ping -c 1 "+host)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n%s", err.Error(), string(output))
	} else {
		fmt.Fprintf(w, "%s", string(output))
	}

	fmt.Fprintf(w, `</pre>
<p><small>Try: localhost; id</small></p>
</body></html>`)
}

func blind(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "localhost"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Blind command injection (no output)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "ping -n 1 "+host)
	} else {
		cmd = exec.Command("sh", "-c", "ping -c 1 "+host)
	}
	cmd.Run() // Output not shown

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Command Injection - Blind</title></head>
<body>
<h1>Ping Test (Blind)</h1>
<form method="GET">
    <input name="host" value="%s" placeholder="Hostname">
    <button type="submit">Ping</button>
</form>
<h2>Result:</h2>
<p>Ping command executed.</p>
<p><small>Try: localhost; sleep 5</small></p>
</body></html>`, host)
}

func fpSanitized(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "localhost"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Command Injection - Safe</title></head>
<body>
<h1>Ping Test (Safe)</h1>
<form method="GET">
    <input name="host" value="%s" placeholder="Hostname">
    <button type="submit">Ping</button>
</form>
<h2>Results:</h2>
<pre>`, host)

	// SAFE: Sanitized - only allow alphanumeric, dots, and hyphens
	sanitized := sanitizeHost(host)
	if sanitized != host {
		fmt.Fprintf(w, "Invalid hostname characters removed.\n\n")
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", sanitized)
	} else {
		cmd = exec.Command("ping", "-c", "1", sanitized)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: ping failed\n%s", string(output))
	} else {
		fmt.Fprintf(w, "%s", string(output))
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func sanitizeHost(host string) string {
	var result strings.Builder
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' {
			result.WriteRune(c)
		}
	}
	return result.String()
}
