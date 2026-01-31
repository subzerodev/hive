# Scanner Analysis UI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a payload visibility system that captures scanner requests and displays what payloads were sent to each vulnerability endpoint.

**Architecture:** Logging middleware captures all requests to SQLite while recording is active. Separate HTTP server on port 8081 serves analysis UI with sessions list, coverage matrix, and endpoint detail views.

**Tech Stack:** Go, SQLite, Go html/template, net/http

---

## Task 1: Create Analysis Database Schema

**Files:**
- Create: `analysis/db.go`

**Step 1: Write the database schema and initialization code**

```go
// analysis/db.go
package analysis

import (
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db   *sql.DB
	dbMu sync.Mutex
)

func InitDB(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS scan_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		started_at DATETIME NOT NULL,
		ended_at DATETIME,
		user_agent TEXT,
		request_count INTEGER DEFAULT 0,
		payload_count INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id INTEGER NOT NULL,
		timestamp DATETIME NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		query_string TEXT,
		headers TEXT,
		body TEXT,
		vuln_category TEXT,
		vuln_endpoint TEXT,
		FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
	);

	CREATE TABLE IF NOT EXISTS baselines (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id INTEGER NOT NULL,
		path TEXT NOT NULL,
		param_name TEXT NOT NULL,
		param_source TEXT NOT NULL,
		baseline_value TEXT NOT NULL,
		first_seen DATETIME NOT NULL,
		UNIQUE(session_id, path, param_name, param_source),
		FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
	);

	CREATE TABLE IF NOT EXISTS payloads (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id INTEGER NOT NULL,
		param_name TEXT NOT NULL,
		param_source TEXT NOT NULL,
		baseline_value TEXT,
		actual_value TEXT NOT NULL,
		normalized_value TEXT,
		UNIQUE(request_id, param_name, param_source),
		FOREIGN KEY (request_id) REFERENCES requests(id)
	);

	CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
	CREATE INDEX IF NOT EXISTS idx_requests_path ON requests(path);
	CREATE INDEX IF NOT EXISTS idx_payloads_request ON payloads(request_id);
	CREATE INDEX IF NOT EXISTS idx_baselines_session_path ON baselines(session_id, path);
	`

	_, err = db.Exec(schema)
	return err
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 3: Commit**

```bash
git add analysis/db.go
git commit -m "feat(analysis): add database schema for scanner analysis"
```

---

## Task 2: Add Session Management

**Files:**
- Modify: `analysis/db.go`
- Create: `analysis/sessions.go`

**Step 1: Add session data types and recording state**

```go
// analysis/sessions.go
package analysis

import (
	"sync"
	"time"
)

type Session struct {
	ID           int64
	Name         string
	StartedAt    time.Time
	EndedAt      *time.Time
	UserAgent    string
	RequestCount int
	PayloadCount int
}

var (
	recording       bool
	recordingMu     sync.RWMutex
	currentSession  *Session
)

func IsRecording() bool {
	recordingMu.RLock()
	defer recordingMu.RUnlock()
	return recording
}

func CurrentSessionID() int64 {
	recordingMu.RLock()
	defer recordingMu.RUnlock()
	if currentSession == nil {
		return 0
	}
	return currentSession.ID
}

func StartRecording(name string) (*Session, error) {
	recordingMu.Lock()
	defer recordingMu.Unlock()

	if recording {
		return currentSession, nil
	}

	now := time.Now()
	result, err := db.Exec(
		"INSERT INTO scan_sessions (name, started_at) VALUES (?, ?)",
		name, now,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	currentSession = &Session{
		ID:        id,
		Name:      name,
		StartedAt: now,
	}
	recording = true

	return currentSession, nil
}

func StopRecording() (*Session, error) {
	recordingMu.Lock()
	defer recordingMu.Unlock()

	if !recording || currentSession == nil {
		return nil, nil
	}

	now := time.Now()
	_, err := db.Exec(
		"UPDATE scan_sessions SET ended_at = ? WHERE id = ?",
		now, currentSession.ID,
	)
	if err != nil {
		return nil, err
	}

	// Update counts
	var reqCount, payloadCount int
	db.QueryRow("SELECT COUNT(*) FROM requests WHERE session_id = ?", currentSession.ID).Scan(&reqCount)
	db.QueryRow("SELECT COUNT(*) FROM payloads p JOIN requests r ON p.request_id = r.id WHERE r.session_id = ?", currentSession.ID).Scan(&payloadCount)

	_, err = db.Exec(
		"UPDATE scan_sessions SET request_count = ?, payload_count = ? WHERE id = ?",
		reqCount, payloadCount, currentSession.ID,
	)

	currentSession.EndedAt = &now
	currentSession.RequestCount = reqCount
	currentSession.PayloadCount = payloadCount

	session := currentSession
	currentSession = nil
	recording = false

	return session, err
}

func GetAllSessions() ([]Session, error) {
	rows, err := db.Query(`
		SELECT id, name, started_at, ended_at, COALESCE(user_agent, ''), request_count, payload_count
		FROM scan_sessions
		ORDER BY started_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var endedAt sql.NullTime
		err := rows.Scan(&s.ID, &s.Name, &s.StartedAt, &endedAt, &s.UserAgent, &s.RequestCount, &s.PayloadCount)
		if err != nil {
			return nil, err
		}
		if endedAt.Valid {
			s.EndedAt = &endedAt.Time
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

func GetSession(id int64) (*Session, error) {
	var s Session
	var endedAt sql.NullTime
	err := db.QueryRow(`
		SELECT id, name, started_at, ended_at, COALESCE(user_agent, ''), request_count, payload_count
		FROM scan_sessions WHERE id = ?
	`, id).Scan(&s.ID, &s.Name, &s.StartedAt, &endedAt, &s.UserAgent, &s.RequestCount, &s.PayloadCount)
	if err != nil {
		return nil, err
	}
	if endedAt.Valid {
		s.EndedAt = &endedAt.Time
	}
	return &s, nil
}

func DeleteSession(id int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete payloads first (foreign key)
	_, err = tx.Exec("DELETE FROM payloads WHERE request_id IN (SELECT id FROM requests WHERE session_id = ?)", id)
	if err != nil {
		return err
	}

	// Delete baselines
	_, err = tx.Exec("DELETE FROM baselines WHERE session_id = ?", id)
	if err != nil {
		return err
	}

	// Delete requests
	_, err = tx.Exec("DELETE FROM requests WHERE session_id = ?", id)
	if err != nil {
		return err
	}

	// Delete session
	_, err = tx.Exec("DELETE FROM scan_sessions WHERE id = ?", id)
	if err != nil {
		return err
	}

	return tx.Commit()
}
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 3: Commit**

```bash
git add analysis/sessions.go
git commit -m "feat(analysis): add session management (start/stop recording)"
```

---

## Task 3: Add Request Capture and Baseline Detection

**Files:**
- Create: `analysis/capture.go`
- Create: `analysis/baseline.go`

**Step 1: Create request capture logic**

```go
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
```

**Step 2: Create baseline detection logic**

```go
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
```

**Step 3: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 4: Commit**

```bash
git add analysis/capture.go analysis/baseline.go
git commit -m "feat(analysis): add request capture and baseline payload detection"
```

---

## Task 4: Add Logging Middleware

**Files:**
- Create: `analysis/middleware.go`

**Step 1: Create the middleware**

```go
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
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 3: Commit**

```bash
git add analysis/middleware.go
git commit -m "feat(analysis): add logging middleware"
```

---

## Task 5: Add Coverage Statistics Queries

**Files:**
- Create: `analysis/stats.go`

**Step 1: Create coverage statistics**

```go
// analysis/stats.go
package analysis

type CategoryCoverage struct {
	Category      string
	TotalEndpoints int
	CrawledEndpoints int
	PayloadCount  int
	Status        string // "full", "partial", "missed"
}

type EndpointDetail struct {
	Path          string
	BaselineParam string
	BaselineValue string
	PayloadCount  int
}

type PayloadGroup struct {
	NormalizedValue string
	Count           int
	Examples        []string
}

// Known HIVE endpoints per category (for coverage calculation)
var knownEndpoints = map[string]int{
	"xss":           28,
	"injection":     50,
	"ssrf":          6,
	"file":          6,
	"auth-session":  15,
	"config":        20,
	"disclosure":    12,
	"redirect":      6,
	"admin":         12,
	"misc":          15,
	"legacy":        14,
	"formhijack":    5,
	"methods":       5,
	"serialization": 3,
	"files":         15,
	"info-disclosure": 10,
	"auth":          25,
}

func GetCategoryCoverage(sessionID int64) ([]CategoryCoverage, error) {
	rows, err := db.Query(`
		SELECT
			vuln_category,
			COUNT(DISTINCT path) as crawled,
			COUNT(DISTINCT CASE WHEN p.id IS NOT NULL THEN r.path END) as with_payloads
		FROM requests r
		LEFT JOIN payloads p ON r.id = p.request_id
		WHERE r.session_id = ? AND vuln_category != ''
		GROUP BY vuln_category
		ORDER BY vuln_category
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var coverages []CategoryCoverage
	for rows.Next() {
		var c CategoryCoverage
		var crawled, withPayloads int
		err := rows.Scan(&c.Category, &crawled, &withPayloads)
		if err != nil {
			continue
		}
		c.CrawledEndpoints = crawled
		c.TotalEndpoints = knownEndpoints[c.Category]
		if c.TotalEndpoints == 0 {
			c.TotalEndpoints = crawled // fallback
		}

		// Count payloads for this category
		db.QueryRow(`
			SELECT COUNT(*) FROM payloads p
			JOIN requests r ON p.request_id = r.id
			WHERE r.session_id = ? AND r.vuln_category = ?
		`, sessionID, c.Category).Scan(&c.PayloadCount)

		// Determine status
		if c.PayloadCount > 0 && crawled >= c.TotalEndpoints {
			c.Status = "full"
		} else if c.PayloadCount > 0 {
			c.Status = "partial"
		} else if crawled > 0 {
			c.Status = "missed"
		} else {
			c.Status = "none"
		}

		coverages = append(coverages, c)
	}
	return coverages, nil
}

func GetEndpointsForCategory(sessionID int64, category string) ([]EndpointDetail, error) {
	rows, err := db.Query(`
		SELECT DISTINCT r.path
		FROM requests r
		WHERE r.session_id = ? AND r.vuln_category = ?
		ORDER BY r.path
	`, sessionID, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []EndpointDetail
	for rows.Next() {
		var e EndpointDetail
		rows.Scan(&e.Path)

		// Get baseline info
		db.QueryRow(`
			SELECT param_name, baseline_value FROM baselines
			WHERE session_id = ? AND path = ?
			LIMIT 1
		`, sessionID, e.Path).Scan(&e.BaselineParam, &e.BaselineValue)

		// Count payloads
		db.QueryRow(`
			SELECT COUNT(*) FROM payloads p
			JOIN requests r ON p.request_id = r.id
			WHERE r.session_id = ? AND r.path = ?
		`, sessionID, e.Path).Scan(&e.PayloadCount)

		endpoints = append(endpoints, e)
	}
	return endpoints, nil
}

func GetPayloadsForEndpoint(sessionID int64, path string) ([]PayloadGroup, error) {
	rows, err := db.Query(`
		SELECT normalized_value, COUNT(*) as cnt, GROUP_CONCAT(actual_value, '|||') as examples
		FROM payloads p
		JOIN requests r ON p.request_id = r.id
		WHERE r.session_id = ? AND r.path = ?
		GROUP BY normalized_value
		ORDER BY cnt DESC
	`, sessionID, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []PayloadGroup
	for rows.Next() {
		var g PayloadGroup
		var examples string
		rows.Scan(&g.NormalizedValue, &g.Count, &examples)

		// Split and limit examples
		parts := strings.Split(examples, "|||")
		if len(parts) > 3 {
			parts = parts[:3]
		}
		g.Examples = parts

		groups = append(groups, g)
	}
	return groups, nil
}

func GetSessionTotalEndpoints(sessionID int64) int {
	var count int
	db.QueryRow("SELECT COUNT(DISTINCT path) FROM requests WHERE session_id = ?", sessionID).Scan(&count)
	return count
}

func GetTotalKnownEndpoints() int {
	total := 0
	for _, v := range knownEndpoints {
		total += v
	}
	return total
}
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 3: Commit**

```bash
git add analysis/stats.go
git commit -m "feat(analysis): add coverage statistics queries"
```

---

## Task 6: Create Analysis UI Templates

**Files:**
- Create: `analysis/templates/layout.html`
- Create: `analysis/templates/sessions.html`
- Create: `analysis/templates/coverage.html`
- Create: `analysis/templates/endpoint.html`

**Step 1: Create layout template**

```html
<!-- analysis/templates/layout.html -->
{{define "layout"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{.Title}} - HIVE Scanner Analysis</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            background: #1a1a2e;
            color: #eee;
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 5px; }
        .subtitle { color: #888; margin-bottom: 20px; }
        a { color: #00d4ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .btn {
            background: #00d4ff;
            color: #1a1a2e;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-weight: bold;
            border-radius: 4px;
        }
        .btn:hover { background: #00a8cc; }
        .btn-danger { background: #ff4757; }
        .btn-danger:hover { background: #ff3344; }
        .recording {
            background: #ff4757;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #16213e; color: #00d4ff; }
        tr:hover { background: #16213e; }
        .status-full { color: #2ed573; }
        .status-partial { color: #ffa502; }
        .status-missed { color: #ff4757; }
        .status-none { color: #666; }
        .card {
            background: #16213e;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .payload-box {
            background: #0f0f23;
            border: 1px solid #333;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
        .count-badge {
            background: #00d4ff;
            color: #1a1a2e;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            margin-left: 10px;
        }
        .back { margin-bottom: 20px; }
        input[type="text"] {
            background: #0f0f23;
            border: 1px solid #333;
            color: #eee;
            padding: 10px;
            border-radius: 4px;
            width: 300px;
        }
        .header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        {{template "content" .}}
    </div>
</body>
</html>
{{end}}
```

**Step 2: Create sessions list template**

```html
<!-- analysis/templates/sessions.html -->
{{define "content"}}
<div class="header-row">
    <div>
        <h1>HIVE Scanner Analysis</h1>
        <p class="subtitle">Payload visibility for security scanner testing</p>
    </div>
    <div>
        {{if .Recording}}
            <span class="recording">● Recording: {{.CurrentSession}}</span>
            <form method="POST" action="/sessions/stop" style="display:inline; margin-left:10px;">
                <button type="submit" class="btn btn-danger">Stop Recording</button>
            </form>
        {{else}}
            <form method="POST" action="/sessions/start" style="display:inline;">
                <input type="text" name="name" placeholder="Session name (e.g., Burp Full Scan)" required>
                <button type="submit" class="btn">Start Recording</button>
            </form>
        {{end}}
    </div>
</div>

{{if .Sessions}}
<table>
    <thead>
        <tr>
            <th>Session</th>
            <th>Scanner</th>
            <th>Requests</th>
            <th>Payloads</th>
            <th>Coverage</th>
            <th>Duration</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {{range .Sessions}}
        <tr>
            <td>
                <strong>{{.Name}}</strong><br>
                <small style="color:#888">{{.StartedAt.Format "2006-01-02 15:04"}}</small>
            </td>
            <td>{{if .UserAgent}}{{.UserAgent}}{{else}}-{{end}}</td>
            <td>{{.RequestCount}}</td>
            <td>{{.PayloadCount}}</td>
            <td>-</td>
            <td>{{if .EndedAt}}{{duration .StartedAt .EndedAt}}{{else}}ongoing{{end}}</td>
            <td>
                <a href="/sessions/{{.ID}}">View →</a>
                {{if .EndedAt}}
                <form method="POST" action="/sessions/{{.ID}}/delete" style="display:inline; margin-left:10px;">
                    <button type="submit" class="btn btn-danger" style="padding:5px 10px; font-size:12px;" onclick="return confirm('Delete this session?')">Delete</button>
                </form>
                {{end}}
            </td>
        </tr>
        {{end}}
    </tbody>
</table>
{{else}}
<div class="card">
    <p>No scan sessions yet. Start recording and run a scanner against HIVE on port 8080.</p>
</div>
{{end}}
{{end}}
```

**Step 3: Create coverage matrix template**

```html
<!-- analysis/templates/coverage.html -->
{{define "content"}}
<div class="back"><a href="/">← Back to Sessions</a></div>

<h1>{{.Session.Name}}</h1>
<p class="subtitle">
    {{.Session.StartedAt.Format "2006-01-02 15:04"}} |
    {{.Session.RequestCount}} requests |
    {{.Session.PayloadCount}} payloads |
    Scanner: {{if .Session.UserAgent}}{{.Session.UserAgent}}{{else}}Unknown{{end}}
</p>

<h2>Coverage Matrix</h2>
<table>
    <thead>
        <tr>
            <th>Category</th>
            <th>Endpoints</th>
            <th>Crawled</th>
            <th>Payloads</th>
            <th>Status</th>
        </tr>
    </thead>
    <tbody>
        {{range .Coverage}}
        <tr>
            <td><a href="/sessions/{{$.Session.ID}}/{{.Category}}">{{.Category}}</a></td>
            <td>{{.TotalEndpoints}}</td>
            <td>{{.CrawledEndpoints}}</td>
            <td>{{.PayloadCount}}</td>
            <td class="status-{{.Status}}">
                {{if eq .Status "full"}}✓ Full{{end}}
                {{if eq .Status "partial"}}⚠ Partial{{end}}
                {{if eq .Status "missed"}}✗ Missed{{end}}
                {{if eq .Status "none"}}- None{{end}}
            </td>
        </tr>
        {{end}}
    </tbody>
</table>

<div class="card">
    <h3>Summary</h3>
    <p>
        <strong>Total Endpoints Crawled:</strong> {{.TotalCrawled}} / {{.TotalKnown}}<br>
        <strong>Coverage:</strong> {{printf "%.0f" .CoveragePercent}}%
    </p>
</div>
{{end}}
```

**Step 4: Create endpoint detail template**

```html
<!-- analysis/templates/endpoint.html -->
{{define "content"}}
<div class="back"><a href="/sessions/{{.Session.ID}}/{{.Category}}">← Back to {{.Category}}</a></div>

<h1>{{.Path}}</h1>
<p class="subtitle">
    Baseline: {{if .Baseline}}{{.Baseline.Param}}={{.Baseline.Value}}{{else}}No baseline set{{end}}
</p>

<h2>Payloads Received ({{.TotalPayloads}})</h2>

{{if .Payloads}}
{{range .Payloads}}
<div class="payload-box">
    <code>{{.NormalizedValue}}</code>
    <span class="count-badge">×{{.Count}}</span>
    {{if gt (len .Examples) 0}}
    <details style="margin-top:10px;">
        <summary style="cursor:pointer; color:#888;">Show examples</summary>
        <ul style="margin-top:5px;">
            {{range .Examples}}
            <li style="word-break:break-all; font-size:12px;">{{.}}</li>
            {{end}}
        </ul>
    </details>
    {{end}}
</div>
{{end}}
{{else}}
<div class="card">
    <p>No payloads detected for this endpoint. Scanner may have only crawled without testing.</p>
</div>
{{end}}
{{end}}
```

**Step 5: Create category listing template**

```html
<!-- analysis/templates/category.html -->
{{define "content"}}
<div class="back"><a href="/sessions/{{.Session.ID}}">← Back to Coverage</a></div>

<h1>{{.Category}}</h1>
<p class="subtitle">{{len .Endpoints}} endpoints crawled</p>

<table>
    <thead>
        <tr>
            <th>Endpoint</th>
            <th>Baseline</th>
            <th>Payloads</th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        {{range .Endpoints}}
        <tr>
            <td><code>{{.Path}}</code></td>
            <td>{{if .BaselineParam}}{{.BaselineParam}}={{.BaselineValue}}{{else}}-{{end}}</td>
            <td>{{.PayloadCount}}</td>
            <td><a href="/sessions/{{$.Session.ID}}/endpoint?path={{.Path}}">View →</a></td>
        </tr>
        {{end}}
    </tbody>
</table>
{{end}}
```

**Step 6: Verify templates exist**

Run: `ls -la /home/subzerodev/workspace/hive/.worktrees/scanner-analysis/analysis/templates/`
Expected: All 5 template files listed

**Step 7: Commit**

```bash
git add analysis/templates/
git commit -m "feat(analysis): add UI templates for sessions, coverage, and endpoint views"
```

---

## Task 7: Create Analysis UI HTTP Handlers

**Files:**
- Create: `analysis/handlers.go`

**Step 1: Create the HTTP handlers**

```go
// analysis/handlers.go
package analysis

import (
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"time"
)

var templates *template.Template

func InitTemplates(templatesDir string) error {
	funcMap := template.FuncMap{
		"duration": func(start, end time.Time) string {
			d := end.Sub(start)
			if d.Hours() >= 1 {
				return strconv.Itoa(int(d.Hours())) + "h " + strconv.Itoa(int(d.Minutes())%60) + "m"
			}
			return strconv.Itoa(int(d.Minutes())) + "m " + strconv.Itoa(int(d.Seconds())%60) + "s"
		},
	}

	var err error
	templates, err = template.New("").Funcs(funcMap).ParseGlob(filepath.Join(templatesDir, "*.html"))
	return err
}

func RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", handleSessions)
	mux.HandleFunc("/sessions/start", handleStartRecording)
	mux.HandleFunc("/sessions/stop", handleStopRecording)
	mux.HandleFunc("/sessions/", handleSessionRoutes)
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	sessions, _ := GetAllSessions()

	data := map[string]interface{}{
		"Title":          "Sessions",
		"Sessions":       sessions,
		"Recording":      IsRecording(),
		"CurrentSession": "",
	}

	if IsRecording() && currentSession != nil {
		data["CurrentSession"] = currentSession.Name
	}

	templates.ExecuteTemplate(w, "layout", data)
}

func handleStartRecording(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		name = "Unnamed Session"
	}

	StartRecording(name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleStopRecording(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	StopRecording()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleSessionRoutes(w http.ResponseWriter, r *http.Request) {
	// Parse: /sessions/{id}, /sessions/{id}/{category}, /sessions/{id}/endpoint, /sessions/{id}/delete
	path := r.URL.Path[len("/sessions/"):]
	parts := splitPath(path)

	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}

	sessionID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	session, err := GetSession(sessionID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 1 {
		// Coverage matrix
		handleCoverage(w, r, session)
		return
	}

	if parts[1] == "delete" && r.Method == "POST" {
		DeleteSession(sessionID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if parts[1] == "endpoint" {
		// Endpoint detail
		handleEndpoint(w, r, session)
		return
	}

	// Category view
	handleCategory(w, r, session, parts[1])
}

func handleCoverage(w http.ResponseWriter, r *http.Request, session *Session) {
	coverage, _ := GetCategoryCoverage(session.ID)
	totalCrawled := GetSessionTotalEndpoints(session.ID)
	totalKnown := GetTotalKnownEndpoints()

	var coveragePercent float64
	if totalKnown > 0 {
		coveragePercent = float64(totalCrawled) / float64(totalKnown) * 100
	}

	data := map[string]interface{}{
		"Title":           session.Name,
		"Session":         session,
		"Coverage":        coverage,
		"TotalCrawled":    totalCrawled,
		"TotalKnown":      totalKnown,
		"CoveragePercent": coveragePercent,
	}

	templates.ExecuteTemplate(w, "layout", data)
}

func handleCategory(w http.ResponseWriter, r *http.Request, session *Session, category string) {
	endpoints, _ := GetEndpointsForCategory(session.ID, category)

	data := map[string]interface{}{
		"Title":     category + " - " + session.Name,
		"Session":   session,
		"Category":  category,
		"Endpoints": endpoints,
	}

	templates.ExecuteTemplate(w, "layout", data)
}

func handleEndpoint(w http.ResponseWriter, r *http.Request, session *Session) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	payloads, _ := GetPayloadsForEndpoint(session.ID, path)

	// Get baseline
	var baseline struct {
		Param string
		Value string
	}
	db.QueryRow(`
		SELECT param_name, baseline_value FROM baselines
		WHERE session_id = ? AND path = ?
		LIMIT 1
	`, session.ID, path).Scan(&baseline.Param, &baseline.Value)

	// Parse category from path
	category, _ := parseVulnPath(path)

	totalPayloads := 0
	for _, p := range payloads {
		totalPayloads += p.Count
	}

	data := map[string]interface{}{
		"Title":         path,
		"Session":       session,
		"Path":          path,
		"Category":      category,
		"Payloads":      payloads,
		"TotalPayloads": totalPayloads,
		"Baseline":      &baseline,
	}

	templates.ExecuteTemplate(w, "layout", data)
}

func splitPath(path string) []string {
	var parts []string
	for _, p := range filepath.SplitList(path) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	// Manual split since SplitList is for PATH env var
	parts = nil
	current := ""
	for _, c := range path {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 3: Commit**

```bash
git add analysis/handlers.go
git commit -m "feat(analysis): add HTTP handlers for analysis UI"
```

---

## Task 8: Create Analysis Server Entry Point

**Files:**
- Create: `analysis/server.go`

**Step 1: Create the server**

```go
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
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build ./analysis/`
Expected: No errors

**Step 3: Commit**

```bash
git add analysis/server.go
git commit -m "feat(analysis): add analysis server entry point"
```

---

## Task 9: Integrate Analysis into Main Application

**Files:**
- Modify: `main.go`

**Step 1: Add analysis imports and initialization**

Add to imports in main.go:
```go
"github.com/subzerodev/hive/analysis"
```

**Step 2: Add analysis initialization after db.Init()**

Add after `db.Init()`:
```go
// Initialize analysis database
analysisDBPath := os.Getenv("ANALYSIS_DB")
if analysisDBPath == "" {
    analysisDBPath = "analysis.db"
}
if err := analysis.InitDB(analysisDBPath); err != nil {
    log.Fatalf("Failed to initialize analysis DB: %v", err)
}
defer analysis.CloseDB()
```

**Step 3: Wrap vulns handler with analysis middleware**

Change the vulnsHandler assignment to wrap with middleware:
```go
// Wrap with analysis middleware
vulnsHandlerWithAnalysis := analysis.Middleware(vulnsHandler)
http.Handle("/vulns/", auth.Middleware(authType, vulnsHandlerWithAnalysis))
```

**Step 4: Start analysis server on separate port**

Add before the main server starts (before `log.Printf("HIVE starting on port %s", port)`):
```go
// Start analysis UI server on separate port
analysisPort := os.Getenv("ANALYSIS_PORT")
if analysisPort == "" {
    analysisPort = "8081"
}
go func() {
    templatesDir := "analysis/templates"
    if err := analysis.StartServer(":"+analysisPort, templatesDir); err != nil {
        log.Printf("Analysis server error: %v", err)
    }
}()
```

**Step 5: Verify it compiles and runs**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build .`
Expected: No errors

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && timeout 3 ./hive 2>&1 || true`
Expected: Should see "HIVE starting on port 8080" and "Analysis UI starting on :8081"

**Step 6: Commit**

```bash
git add main.go
git commit -m "feat: integrate analysis middleware and UI server into main app"
```

---

## Task 10: Final Integration Test

**Step 1: Build and run HIVE**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/scanner-analysis && go build . && ./hive &`
Expected: Both servers start

**Step 2: Test analysis UI loads**

Run: `curl -s http://localhost:8081/ | head -20`
Expected: HTML with "HIVE Scanner Analysis" title

**Step 3: Test recording start**

Run: `curl -s -X POST -d "name=Test Session" http://localhost:8081/sessions/start -w "%{redirect_url}"`
Expected: Redirect to /

**Step 4: Send a test request to HIVE**

Run: `curl -s "http://localhost:8080/vulns/xss/reflected/html-body?name=TestValue"`
Expected: HTML response

**Step 5: Send a payload request**

Run: `curl -s "http://localhost:8080/vulns/xss/reflected/html-body?name=<script>alert(1)</script>"`
Expected: HTML response with payload reflected

**Step 6: Stop recording**

Run: `curl -s -X POST http://localhost:8081/sessions/stop`

**Step 7: Check session was recorded**

Run: `curl -s http://localhost:8081/ | grep "Test Session"`
Expected: Session visible in list

**Step 8: Stop HIVE**

Run: `pkill -f "./hive"`

**Step 9: Commit final state**

```bash
git add -A
git commit -m "test: verify analysis system integration" --allow-empty
```

---

## Summary

This plan implements:
1. SQLite database for storing scan sessions, requests, baselines, and payloads
2. Middleware that captures requests when recording is active
3. Baseline detection (first unique value per parameter)
4. Payload normalization (canaries replaced with {N})
5. Web UI on port 8081 with sessions list, coverage matrix, and endpoint detail views
6. Manual start/stop recording control

**Total files created:** 11
- `analysis/db.go`
- `analysis/sessions.go`
- `analysis/capture.go`
- `analysis/baseline.go`
- `analysis/middleware.go`
- `analysis/stats.go`
- `analysis/handlers.go`
- `analysis/server.go`
- `analysis/templates/layout.html`
- `analysis/templates/sessions.html`
- `analysis/templates/coverage.html`
- `analysis/templates/category.html`
- `analysis/templates/endpoint.html`

**Files modified:** 1
- `main.go`
