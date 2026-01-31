// analysis/server.go
package analysis

import (
	"log"
	"net/http"
)

func StartServer(addr string, templatesDir string) error {
	if err := InitTemplates(templatesDir); err != nil {
		return err
	}

	mux := http.NewServeMux()
	RegisterHandlers(mux)

	log.Printf("Analysis UI starting on %s", addr)
	return http.ListenAndServe(addr, mux)
}
