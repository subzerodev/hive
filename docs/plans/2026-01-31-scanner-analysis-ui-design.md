# Scanner Analysis UI Design

**Date:** 2026-01-31
**Status:** Approved

## Overview

A payload visibility system for HIVE that captures scanner requests and displays what payloads were sent to each vulnerability endpoint. Helps evaluate scanner coverage, learn scanner techniques, and develop/tune scanners.

## Architecture

Two components on separate ports:

| Component | Port | Purpose |
|-----------|------|---------|
| HIVE (existing) | 8080 | Vulnerability testbed, serves scanners |
| Analysis UI | 8081 | View captured requests, invisible to scanners |

**Data flow:**
```
Scanner → HIVE:8080 → Logging Middleware → SQLite DB
                                              ↓
                        You → Analysis UI:8081 ← reads
```

## Session Control

Manual start/stop recording:
- UI has "Start Recording" / "Stop Recording" button
- Only captures requests while recording is active
- User names each session (e.g., "Burp Full Scan", "ZAP Quick Test")

## Baseline Detection

How payloads are identified:
- Track unique parameter values per endpoint
- First unique value = baseline (e.g., `name=Guest`)
- Any different value = payload (e.g., `name=<script>alert(1)</script>`)
- Multiple crawl requests with same value all match baseline

## Data Model

```sql
-- Scan sessions
scan_sessions (
    id              INTEGER PRIMARY KEY,
    name            TEXT,
    started_at      DATETIME,
    ended_at        DATETIME,
    user_agent      TEXT,
    request_count   INTEGER,
    payload_count   INTEGER
)

-- Every request captured
requests (
    id              INTEGER PRIMARY KEY,
    session_id      INTEGER,
    timestamp       DATETIME,
    method          TEXT,
    path            TEXT,
    query_string    TEXT,
    headers         TEXT,        -- JSON blob
    body            TEXT,
    vuln_category   TEXT,        -- "xss", "sqli", "command", etc.
    vuln_endpoint   TEXT
)

-- Baselines (first unique value per param)
baselines (
    id              INTEGER PRIMARY KEY,
    session_id      INTEGER,
    path            TEXT,
    param_name      TEXT,
    param_source    TEXT,        -- "query", "body", "header"
    baseline_value  TEXT,
    first_seen      DATETIME
)

-- Detected payloads (deviations from baseline)
payloads (
    id              INTEGER PRIMARY KEY,
    request_id      INTEGER,
    param_name      TEXT,
    baseline_value  TEXT,
    actual_value    TEXT,
    normalized_value TEXT,       -- canaries replaced with {N}
    UNIQUE(request_id, param_name)
)
```

## UI Views

### View 1: Sessions List (landing page)

```
┌─────────────────────────────────────────────────────────────────┐
│  HIVE Scanner Analysis                    [Start Recording]     │
├─────────────────────────────────────────────────────────────────┤
│  Session              │ Requests │ Payloads │ Coverage │ Duration│
│  ─────────────────────────────────────────────────────────────  │
│  Burp Full Scan       │    1,247 │      892 │    78%   │ 12m 34s │
│  2026-01-31 19:01                                      [View →] │
│  ─────────────────────────────────────────────────────────────  │
│  ZAP Quick Test       │      634 │      412 │    52%   │  8m 12s │
│  2026-01-30 14:22                                      [View →] │
└─────────────────────────────────────────────────────────────────┘
```

### View 2: Coverage Matrix

```
┌─────────────────────────────────────────────────────────────────┐
│  Burp Full Scan - Coverage Matrix                               │
├─────────────────────────────────────────────────────────────────┤
│  Category          │ Endpoints │ Crawled │ Payloads │ Status    │
│  ──────────────────────────────────────────────────────────────  │
│  xss/reflected     │     4     │    4    │    127   │ ✓ Full    │
│  xss/stored        │     2     │    2    │     34   │ ✓ Full    │
│  injection/sqli    │    16     │   13    │    201   │ ⚠ Partial │
│  injection/xxe     │     3     │    3    │      0   │ ✗ Missed  │
│  injection/ssti    │     4     │    4    │      0   │ ✗ Missed  │
│  ssrf              │     6     │    4    │     12   │ ⚠ Partial │
└─────────────────────────────────────────────────────────────────┘
```

### View 3: Endpoint Detail

```
┌─────────────────────────────────────────────────────────────────┐
│  /vulns/xss/reflected/html-body                                 │
│  Baseline: name=Guest                                           │
├─────────────────────────────────────────────────────────────────┤
│  Payloads received (47):                                        │
│  ──────────────────────────────────────────────────────────────  │
│  <script>alert({N})</script>                             ×12    │
│  <img src=x onerror=alert({N})>                          ×8     │
│  <svg/onload=alert({N})>                                 ×6     │
│  "><script>alert({N})</script>                           ×5     │
│  javascript:alert({N})                                   ×4     │
│  ... [Show all]                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Components

### New files

```
/analysis/
    middleware.go      # Request capture middleware
    db.go              # SQLite schema + queries
    sessions.go        # Start/stop recording, session management
    handlers.go        # UI route handlers
    baseline.go        # Baseline detection logic
    templates/
        layout.html    # Common page structure
        sessions.html  # Sessions list view
        coverage.html  # Coverage matrix view
        endpoint.html  # Endpoint detail view
```

### Changes to existing code

```
main.go
    - Add analysis middleware wrapping vulns handler
    - Start analysis UI server on port 8081
```

### Middleware logic

```go
func AnalysisMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if IsRecording() {
            CaptureRequest(r)
        }
        next.ServeHTTP(w, r)
    })
}
```

## Analysis UI API

**Endpoints (port 8081):**

```
GET  /                      # Sessions list
POST /sessions/start        # Start recording (name param)
POST /sessions/stop         # Stop recording
GET  /sessions/:id          # Coverage matrix for session
GET  /sessions/:id/:category# Endpoint list for category
GET  /sessions/:id/endpoint # Endpoint detail (path as query param)
POST /sessions/:id/delete   # Delete a session
GET  /export/:id            # Export session as JSON/CSV
```

## Payload Normalization

Canary/tag handling for grouping:
- Replace random strings/numbers with `{N}`
- `<script>alert(12345)</script>` → `<script>alert({N})</script>`
- Group by normalized form, show count of variations

## Tech Stack

- Go templates for UI (consistent with HIVE)
- SQLite for storage (already used by HIVE)
- Minimal JS for start/stop buttons, no framework needed
