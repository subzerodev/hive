// analysis/capture.go
package analysis

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type CapturedRequest struct {
	ID           int64
	SessionID    int64
	Timestamp    time.Time
	Method       string
	Path         string
	QueryString  string
	Headers      map[string]string
	Body         string
	VulnCategory string
	VulnEndpoint string
}

func CaptureRequest(r *http.Request) (*CapturedRequest, error) {
	sessionID := CurrentSessionID()
	if sessionID == 0 {
		return nil, nil
	}

	// Read body
	var body string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		body = string(bodyBytes)
		// Restore body for downstream handlers
		r.Body = io.NopCloser(strings.NewReader(body))
	}

	// Extract headers
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	headersJSON, _ := json.Marshal(headers)

	// Parse vulnerability category from path
	vulnCategory, vulnEndpoint := parseVulnPath(r.URL.Path)

	// Update session user-agent on first request
	if ua := r.Header.Get("User-Agent"); ua != "" {
		db.Exec("UPDATE scan_sessions SET user_agent = ? WHERE id = ? AND user_agent IS NULL", ua, sessionID)
	}

	// Insert request
	result, err := db.Exec(`
		INSERT INTO requests (session_id, timestamp, method, path, query_string, headers, body, vuln_category, vuln_endpoint)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, time.Now(), r.Method, r.URL.Path, r.URL.RawQuery, string(headersJSON), body, vulnCategory, vulnEndpoint)
	if err != nil {
		return nil, err
	}

	reqID, _ := result.LastInsertId()
	captured := &CapturedRequest{
		ID:           reqID,
		SessionID:    sessionID,
		Timestamp:    time.Now(),
		Method:       r.Method,
		Path:         r.URL.Path,
		QueryString:  r.URL.RawQuery,
		Headers:      headers,
		Body:         body,
		VulnCategory: vulnCategory,
		VulnEndpoint: vulnEndpoint,
	}

	// Detect payloads
	DetectPayloads(captured, r)

	return captured, nil
}

func parseVulnPath(path string) (category, endpoint string) {
	// /vulns/xss/reflected/html-body -> category="xss", endpoint="reflected/html-body"
	path = strings.TrimPrefix(path, "/vulns/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) >= 1 {
		category = parts[0]
	}
	if len(parts) >= 2 {
		endpoint = parts[1]
	}
	return
}
