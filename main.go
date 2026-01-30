// main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/subzerodev/hive/api"
	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"

	_ "github.com/subzerodev/hive/vulns/injection/sqli/mssql"
	_ "github.com/subzerodev/hive/vulns/injection/sqli/mysql"
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

	// Static files with directory listing enabled
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// API endpoints
	http.HandleFunc("/api/reset", api.ResetHandler)

	// Dynamic vulnerability handlers (must be before static vulns file server)
	http.Handle("/vulns/injection/", handlers.Mux())

	// Vulnerability test cases
	vulnsFs := http.FileServer(http.Dir("./vulns"))
	http.Handle("/vulns/", http.StripPrefix("/vulns/", vulnsFs))

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
