// analysis/sessions.go
package analysis

import (
	"database/sql"
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

// ResumeIncompleteSession checks for a session without ended_at and resumes recording
func ResumeIncompleteSession() error {
	recordingMu.Lock()
	defer recordingMu.Unlock()

	if recording {
		return nil // Already recording
	}

	var s Session
	err := db.QueryRow(`
		SELECT id, name, started_at, COALESCE(user_agent, '')
		FROM scan_sessions
		WHERE ended_at IS NULL
		ORDER BY started_at DESC
		LIMIT 1
	`).Scan(&s.ID, &s.Name, &s.StartedAt, &s.UserAgent)

	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil // No incomplete session, that's fine
		}
		return err
	}

	// Resume the session
	currentSession = &Session{
		ID:        s.ID,
		Name:      s.Name,
		StartedAt: s.StartedAt,
		UserAgent: s.UserAgent,
	}
	recording = true

	return nil
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
