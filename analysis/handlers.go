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
		"View":           "sessions",
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
		"View":            "coverage",
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
		"View":      "category",
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
		"View":          "endpoint",
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
