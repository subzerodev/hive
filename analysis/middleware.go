// analysis/middleware.go
package analysis

import (
	"net/http"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsRecording() {
			CaptureRequest(r)
		}
		next.ServeHTTP(w, r)
	})
}
