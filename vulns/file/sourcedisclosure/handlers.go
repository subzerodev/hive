package sourcedisclosure

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/file/source-disclosure/backup", backup)
	})
}

func backup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: Source code in backup file
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Source Disclosure - Backup Files</title></head>
<body>
<h1>Source Disclosure via Backup Files</h1>
<p>Backup files may expose source code:</p>
<ul>
    <li><a href="/static/backup-files/config.php.bak">config.php.bak</a></li>
    <li><a href="/static/backup-files/database.sql.old">database.sql.old</a></li>
</ul>
<h2>False Positives:</h2>
<ul>
    <li><a href="/static/backup-files/fp/readme.txt.pdf">readme.txt.pdf</a> - Not a backup file</li>
</ul>
</body></html>`)
}
