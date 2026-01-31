// analysis/db.go
package analysis

import (
	"database/sql"
	"sync"

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
