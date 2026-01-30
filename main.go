// main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/subzerodev/hive/api"
	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"

	_ "github.com/subzerodev/hive/vulns/injection/command"
	_ "github.com/subzerodev/hive/vulns/injection/code"
	_ "github.com/subzerodev/hive/vulns/injection/hpp"
	_ "github.com/subzerodev/hive/vulns/injection/sqli/mssql"
	_ "github.com/subzerodev/hive/vulns/injection/sqli/mysql"
	_ "github.com/subzerodev/hive/vulns/injection/sqli/postgres"
	_ "github.com/subzerodev/hive/vulns/injection/sqli/sqlite"
	_ "github.com/subzerodev/hive/vulns/injection/ssti"
	_ "github.com/subzerodev/hive/vulns/injection/xpath"
	_ "github.com/subzerodev/hive/vulns/injection/xxe"
	_ "github.com/subzerodev/hive/vulns/xss/blacklist"
	_ "github.com/subzerodev/hive/vulns/xss/context"
	_ "github.com/subzerodev/hive/vulns/xss/dom"
	_ "github.com/subzerodev/hive/vulns/xss/headers"
	_ "github.com/subzerodev/hive/vulns/xss/reflected"
	_ "github.com/subzerodev/hive/vulns/xss/stored"

	_ "github.com/subzerodev/hive/vulns/file/pathtraversal"
	_ "github.com/subzerodev/hive/vulns/file/sourcedisclosure"
	_ "github.com/subzerodev/hive/vulns/file/upload"

	_ "github.com/subzerodev/hive/vulns/authsession/authbypass"
	_ "github.com/subzerodev/hive/vulns/authsession/cookieflags"
	_ "github.com/subzerodev/hive/vulns/authsession/csrf"
	_ "github.com/subzerodev/hive/vulns/authsession/passwordexposure"
	_ "github.com/subzerodev/hive/vulns/authsession/sessioninurl"

	_ "github.com/subzerodev/hive/vulns/infodisclosure/errormessages"
	_ "github.com/subzerodev/hive/vulns/infodisclosure/pii"
	_ "github.com/subzerodev/hive/vulns/infodisclosure/versiondisclosure"

	_ "github.com/subzerodev/hive/vulns/config/cors"
	_ "github.com/subzerodev/hive/vulns/config/csp"
	_ "github.com/subzerodev/hive/vulns/config/clickjacking"
	_ "github.com/subzerodev/hive/vulns/config/httpmethods"
	_ "github.com/subzerodev/hive/vulns/config/hostheader"
	_ "github.com/subzerodev/hive/vulns/config/openredirect"
	_ "github.com/subzerodev/hive/vulns/config/contenttype"

	_ "github.com/subzerodev/hive/vulns/auth/formpost"
	_ "github.com/subzerodev/hive/vulns/auth/ajaxjson"
	_ "github.com/subzerodev/hive/vulns/auth/multistep"
	_ "github.com/subzerodev/hive/vulns/auth/oauth"
	_ "github.com/subzerodev/hive/vulns/auth/httpbasic"
	_ "github.com/subzerodev/hive/vulns/auth/jwt"

	_ "github.com/subzerodev/hive/vulns/redirect"
	_ "github.com/subzerodev/hive/vulns/serialization"
	_ "github.com/subzerodev/hive/vulns/ssrf"

	_ "github.com/subzerodev/hive/vulns/injection/ldap"
	_ "github.com/subzerodev/hive/vulns/injection/ssi"
	_ "github.com/subzerodev/hive/vulns/injection/ssjs"
	_ "github.com/subzerodev/hive/vulns/injection/css"

	_ "github.com/subzerodev/hive/vulns/config/headers"
	_ "github.com/subzerodev/hive/vulns/formhijack"
	_ "github.com/subzerodev/hive/vulns/disclosure"
	_ "github.com/subzerodev/hive/vulns/files"
	_ "github.com/subzerodev/hive/vulns/admin"
	_ "github.com/subzerodev/hive/vulns/methods"
	_ "github.com/subzerodev/hive/vulns/misc"
	_ "github.com/subzerodev/hive/vulns/legacy"
)

func main() {
	// Initialize databases
	db.Init()
	defer db.Close()

	// Initialize handlers
	handlers.Init()

	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Robots.txt and sitemap.xml
	http.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "robots.txt")
	})
	http.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "sitemap.xml")
	})

	// Flash and Silverlight cross-domain policies (legacy but still scanned)
	http.HandleFunc("/crossdomain.xml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "crossdomain.xml")
	})
	http.HandleFunc("/clientaccesspolicy.xml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "clientaccesspolicy.xml")
	})

	// Static files with directory listing enabled
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// API endpoints
	http.HandleFunc("/api/reset", api.ResetHandler)

	// Combined handler for /vulns/ - serves static files first, then dynamic handlers
	vulnsFs := http.FileServer(http.Dir("./vulns"))
	http.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/vulns/")

		// Check if this is a static file request (ends with / or has extension)
		if path == "" || strings.HasSuffix(path, "/") || strings.HasSuffix(path, ".html") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") {
			// Check if the file exists
			filePath := "./vulns/" + path
			if strings.HasSuffix(path, "/") {
				filePath += "index.html"
			}
			if _, err := os.Stat(filePath); err == nil {
				http.StripPrefix("/vulns/", vulnsFs).ServeHTTP(w, r)
				return
			}
		}

		// Try dynamic handler
		handlers.Mux().ServeHTTP(w, r)
	})

	// Root redirect to vulns
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/vulns/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down...")
		db.Close()
		os.Exit(0)
	}()

	log.Printf("HIVE starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
