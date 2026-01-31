// analysis/baseline.go
package analysis

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func DetectPayloads(captured *CapturedRequest, r *http.Request) {
	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			checkAndRecordPayload(captured, key, "query", value)
		}
	}

	// Check POST form data
	if r.Method == "POST" && strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		formValues, _ := url.ParseQuery(captured.Body)
		for key, values := range formValues {
			for _, value := range values {
				checkAndRecordPayload(captured, key, "body", value)
			}
		}
	}

	// Check JSON body params (simplified - just check for common patterns in body)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") && captured.Body != "" {
		checkAndRecordPayload(captured, "_body", "json", captured.Body)
	}
}

func checkAndRecordPayload(captured *CapturedRequest, paramName, paramSource, value string) {
	dbMu.Lock()
	defer dbMu.Unlock()

	// Try to get or set baseline
	var baselineValue string
	err := db.QueryRow(`
		SELECT baseline_value FROM baselines
		WHERE session_id = ? AND path = ? AND param_name = ? AND param_source = ?
	`, captured.SessionID, captured.Path, paramName, paramSource).Scan(&baselineValue)

	if err != nil {
		// No baseline exists - this is the first unique value, set it as baseline
		db.Exec(`
			INSERT OR IGNORE INTO baselines (session_id, path, param_name, param_source, baseline_value, first_seen)
			VALUES (?, ?, ?, ?, ?, ?)
		`, captured.SessionID, captured.Path, paramName, paramSource, value, time.Now())
		return
	}

	// Baseline exists - check if this value differs
	if value != baselineValue {
		// This is a payload!
		normalized := normalizePayload(value)
		db.Exec(`
			INSERT OR IGNORE INTO payloads (request_id, param_name, param_source, baseline_value, actual_value, normalized_value)
			VALUES (?, ?, ?, ?, ?, ?)
		`, captured.ID, paramName, paramSource, baselineValue, value, normalized)
	}
}

// normalizePayload replaces canaries/random values with {N} for grouping
func normalizePayload(value string) string {
	// Replace numbers that look like canaries (4+ digits)
	re := regexp.MustCompile(`\d{4,}`)
	normalized := re.ReplaceAllString(value, "{N}")

	// Replace random alphanumeric strings (8+ chars of mixed case/numbers)
	re2 := regexp.MustCompile(`[a-zA-Z0-9]{8,}`)
	normalized = re2.ReplaceAllStringFunc(normalized, func(s string) string {
		// Only replace if it looks random (has both letters and numbers)
		hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(s)
		hasDigit := regexp.MustCompile(`\d`).MatchString(s)
		if hasLetter && hasDigit {
			return "{CANARY}"
		}
		return s
	})

	return normalized
}
