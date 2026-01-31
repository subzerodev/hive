// analysis/stats.go
package analysis

import "strings"

type CategoryCoverage struct {
	Category         string
	TotalEndpoints   int
	CrawledEndpoints int
	PayloadCount     int
	Status           string // "full", "partial", "missed"
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
	"xss":             28,
	"injection":       50,
	"ssrf":            6,
	"file":            6,
	"auth-session":    15,
	"config":          20,
	"disclosure":      12,
	"redirect":        6,
	"admin":           12,
	"misc":            15,
	"legacy":          14,
	"formhijack":      5,
	"methods":         5,
	"serialization":   3,
	"files":           15,
	"info-disclosure": 10,
	"auth":            25,
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
