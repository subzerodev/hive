// handlers/handlers.go
package handlers

import (
	"net/http"
	"sync"
)

var (
	mux     = http.NewServeMux()
	once    sync.Once
	initFns []func()
)

// Register adds an init function to be called during setup
func Register(fn func()) {
	initFns = append(initFns, fn)
}

// Init calls all registered init functions
func Init() {
	once.Do(func() {
		for _, fn := range initFns {
			fn()
		}
	})
}

// Handle registers a handler for a pattern
func Handle(pattern string, handler http.HandlerFunc) {
	mux.HandleFunc(pattern, handler)
}

// Mux returns the handler mux
func Mux() *http.ServeMux {
	return mux
}
