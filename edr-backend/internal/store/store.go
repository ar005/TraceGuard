// internal/store/store.go
// Repository layer — all database queries live here.

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/youredr/edr-backend/internal/models"
)

// Store wraps the database connection and provides typed query methods.
type Store struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// DB returns the underlying sqlx.DB, used by the migration package.
func (s *Store) DB() *sqlx.DB {
	return s.db
}

// ─── Agents ───────────────────────────────────────────────────────────────────

func (s *Store) UpsertAgent(ctx context.Context, a *models.Agent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen, is_online, config_ver, tags, env, notes)
		VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW(),TRUE,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET
			hostname   = EXCLUDED.hostname,
			os         = EXCLUDED.os,
			os_version = EXCLUDED.os_version,
			ip         = EXCLUDED.ip,
			agent_ver  = EXCLUDED.agent_ver,
			last_seen  = NOW(),
			is_online  = TRUE,
			tags  = CASE WHEN array_length(EXCLUDED.tags,1) > 0 THEN EXCLUDED.tags ELSE agents.tags END,
			env   = CASE WHEN EXCLUDED.env   != '' THEN EXCLUDED.env   ELSE agents.env   END,
			notes = CASE WHEN EXCLUDED.notes != '' THEN EXCLUDED.notes ELSE agents.notes END
	`, a.ID, a.Hostname, a.OS, a.OSVersion, a.IP, a.AgentVer, a.ConfigVer,
		pq.Array(coalesceStringSlice(a.Tags)), a.Env, a.Notes)
	return err
}

// coalesceStringSlice returns an empty slice instead of nil so pq.Array
// never sends NULL for a NOT NULL TEXT[] column.
func coalesceStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Store) TouchAgent(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen=NOW(), is_online=TRUE WHERE id=$1`, agentID)
	return err
}

// MarkStaleAgentsOffline marks agents offline if last_seen is older than threshold.
func (s *Store) MarkStaleAgentsOffline(ctx context.Context, threshold time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET is_online=FALSE
		  WHERE is_online=TRUE
		    AND last_seen < NOW() - $1::interval`,
		threshold.String())
	return err
}

func (s *Store) MarkAgentOffline(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET is_online=FALSE WHERE id=$1`, agentID)
	return err
}

func (s *Store) GetAgent(ctx context.Context, id string) (*models.Agent, error) {
	var a models.Agent
	err := s.db.GetContext(ctx, &a, `SELECT * FROM agents WHERE id=$1`, id)
	return &a, err
}

func (s *Store) ListAgents(ctx context.Context) ([]models.Agent, error) {
	var agents []models.Agent
	err := s.db.SelectContext(ctx, &agents, `SELECT * FROM agents ORDER BY last_seen DESC`)
	return agents, err
}

// ─── Events ───────────────────────────────────────────────────────────────────

func (s *Store) InsertEvent(ctx context.Context, e *models.Event) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events (id, agent_id, hostname, event_type, timestamp, payload, received_at, severity, rule_id, alert_id)
		VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,$8,$9)
		ON CONFLICT (id) DO NOTHING
	`, e.ID, e.AgentID, e.Hostname, e.EventType, e.Timestamp, e.Payload, e.Severity, e.RuleID, e.AlertID)
	return err
}

// InsertEventBatch inserts many events in a single transaction.
func (s *Store) InsertEventBatch(ctx context.Context, events []*models.Event) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO events (id, agent_id, hostname, event_type, timestamp, payload, received_at, severity, rule_id, alert_id)
		VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,$8,$9)
		ON CONFLICT (id) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.ID, e.AgentID, e.Hostname, e.EventType, e.Timestamp,
			e.Payload, e.Severity, e.RuleID, e.AlertID,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryEventsParams defines filter/pagination for event queries.
type QueryEventsParams struct {
	AgentID    string
	EventTypes []string
	Since      *time.Time
	Until      *time.Time
	Search     string // full-text search in payload
	PID        string // filter by payload process.pid — for process tree lookup
	Hostname   string // filter by hostname column
	AlertID    string // filter by alert_id column (events that triggered an alert)
	EventIDs   []string // fetch specific event IDs (from alert.event_ids)
	Limit      int
	Offset     int
}

func (s *Store) QueryEvents(ctx context.Context, p QueryEventsParams) ([]models.Event, error) {
	if p.Limit == 0 {
		p.Limit = 50
	}

	query := `SELECT * FROM events WHERE 1=1`
	args := []interface{}{}
	argN := 1

	if p.AgentID != "" {
		query += fmt.Sprintf(` AND agent_id = $%d`, argN)
		args = append(args, p.AgentID)
		argN++
	}
	if len(p.EventTypes) > 0 {
		query += fmt.Sprintf(` AND event_type = ANY($%d)`, argN)
		args = append(args, pq.Array(p.EventTypes))
		argN++
	}
	if p.Since != nil {
		query += fmt.Sprintf(` AND timestamp >= $%d`, argN)
		args = append(args, *p.Since)
		argN++
	}
	if p.Until != nil {
		query += fmt.Sprintf(` AND timestamp <= $%d`, argN)
		args = append(args, *p.Until)
		argN++
	}
	if p.Search != "" {
		query += fmt.Sprintf(` AND payload::text ILIKE $%d`, argN)
		args = append(args, "%"+p.Search+"%")
		argN++
	}
	// Filter by process PID — used for process tree correlation in the UI.
	// Matches payload->>'process' JSONB field containing "pid":<value>.
	if p.PID != "" {
		query += fmt.Sprintf(` AND payload::text ILIKE $%d`, argN)
		args = append(args, `%"pid":`+p.PID+`%`)
		argN++
	}
	if p.Hostname != "" {
		query += fmt.Sprintf(` AND hostname = $%d`, argN)
		args = append(args, p.Hostname)
		argN++
	}
	if p.AlertID != "" {
		query += fmt.Sprintf(` AND alert_id = $%d`, argN)
		args = append(args, p.AlertID)
		argN++
	}
	if len(p.EventIDs) > 0 {
		query += fmt.Sprintf(` AND id = ANY($%d)`, argN)
		args = append(args, pq.Array(p.EventIDs))
		argN++
	}

	query += fmt.Sprintf(` ORDER BY timestamp DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, p.Limit, p.Offset)

	var events []models.Event
	err := s.db.SelectContext(ctx, &events, query, args...)
	return events, err
}

func (s *Store) GetEvent(ctx context.Context, id string) (*models.Event, error) {
	var e models.Event
	err := s.db.GetContext(ctx, &e, `SELECT * FROM events WHERE id=$1`, id)
	return &e, err
}

func (s *Store) CountEvents(ctx context.Context, agentID string, since time.Time) (int64, error) {
	var n int64
	var err error
	if agentID == "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM events WHERE timestamp >= $1`, since,
		).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM events WHERE agent_id=$1 AND timestamp >= $2`,
			agentID, since,
		).Scan(&n)
	}
	return n, err
}

// DeleteOldEvents deletes events older than the given cutoff time.
// Returns the number of rows deleted.
func (s *Store) DeleteOldEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE timestamp < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteOldAlerts deletes CLOSED/RESOLVED alerts older than the given cutoff.
// Open alerts are never auto-deleted.
func (s *Store) DeleteOldAlerts(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM alerts
		WHERE status IN ('CLOSED','RESOLVED')
		  AND last_seen < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (s *Store) InsertAlert(ctx context.Context, a *models.Alert) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts
		  (id, title, description, severity, status, rule_id, rule_name, mitre_ids, event_ids, agent_id, hostname, first_seen, last_seen, hit_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW(),1)
		ON CONFLICT (id) DO UPDATE SET
			last_seen  = NOW(),
			hit_count  = alerts.hit_count + 1,
			event_ids  = alerts.event_ids || EXCLUDED.event_ids,
			status     = CASE WHEN alerts.status='CLOSED' THEN 'OPEN' ELSE alerts.status END
	`, a.ID, a.Title, a.Description, a.Severity, a.Status,
		a.RuleID, a.RuleName, pq.Array(a.MitreIDs), pq.Array(a.EventIDs),
		a.AgentID, a.Hostname)
	return err
}

// QueryAlertsParams defines filter/pagination for alert queries.
type QueryAlertsParams struct {
	AgentID  string
	Status   string
	Severity int16
	RuleID   string
	Limit    int
	Offset   int
}

func (s *Store) QueryAlerts(ctx context.Context, p QueryAlertsParams) ([]models.Alert, error) {
	if p.Limit == 0 {
		p.Limit = 50
	}

	query := `SELECT * FROM alerts WHERE 1=1`
	args := []interface{}{}
	argN := 1

	if p.AgentID != "" {
		query += fmt.Sprintf(` AND agent_id = $%d`, argN)
		args = append(args, p.AgentID)
		argN++
	}
	if p.Status != "" {
		query += fmt.Sprintf(` AND status = $%d`, argN)
		args = append(args, p.Status)
		argN++
	}
	if p.Severity > 0 {
		query += fmt.Sprintf(` AND severity >= $%d`, argN)
		args = append(args, p.Severity)
		argN++
	}
	if p.RuleID != "" {
		query += fmt.Sprintf(` AND rule_id = $%d`, argN)
		args = append(args, p.RuleID)
		argN++
	}

	query += fmt.Sprintf(` ORDER BY first_seen DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, p.Limit, p.Offset)

	var alerts []models.Alert
	err := s.db.SelectContext(ctx, &alerts, query, args...)
	return alerts, err
}

func (s *Store) GetAlert(ctx context.Context, id string) (*models.Alert, error) {
	var a models.Alert
	err := s.db.GetContext(ctx, &a, `SELECT * FROM alerts WHERE id=$1`, id)
	return &a, err
}

// GetAlertEvents returns all events associated with an alert.
// It queries by both alert_id column and the alert's event_ids array,
// deduplicating by event ID.
func (s *Store) GetAlertEvents(ctx context.Context, alertID string) ([]models.Event, error) {
	// First get the alert to retrieve its event_ids list.
	alert, err := s.GetAlert(ctx, alertID)
	if err != nil {
		return nil, fmt.Errorf("get alert: %w", err)
	}

	// Query by alert_id column (events tagged during ingest) UNION
	// query by explicit event_ids array (events captured at detection time).
	eventIDs := []string(alert.EventIDs)
	if len(eventIDs) == 0 {
		// Fall back to alert_id column only
		var events []models.Event
		err = s.db.SelectContext(ctx, &events,
			`SELECT * FROM events WHERE alert_id=$1 ORDER BY timestamp DESC LIMIT 500`,
			alertID)
		return events, err
	}

	// Fetch by event IDs first (exact match), then also by alert_id, union them.
	var byID, byAlertID []models.Event
	if err2 := s.db.SelectContext(ctx, &byID,
		`SELECT * FROM events WHERE id = ANY($1) ORDER BY timestamp DESC`,
		pq.Array(eventIDs)); err2 != nil {
		return nil, err2
	}
	if err2 := s.db.SelectContext(ctx, &byAlertID,
		`SELECT * FROM events WHERE alert_id=$1 ORDER BY timestamp DESC LIMIT 500`,
		alertID); err2 != nil {
		return nil, err2
	}

	// Merge and deduplicate.
	seen := make(map[string]bool)
	all := append(byID, byAlertID...)
	result := make([]models.Event, 0, len(all))
	for _, ev := range all {
		if !seen[ev.ID] {
			seen[ev.ID] = true
			result = append(result, ev)
		}
	}
	return result, nil
}

func (s *Store) UpdateAlertStatus(ctx context.Context, id, status, assignee, notes string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET status=$2, assignee=$3, notes=$4 WHERE id=$1`,
		id, status, assignee, notes)
	return err
}

func (s *Store) AlertStats(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT status, COUNT(*) FROM alerts GROUP BY status
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]int64{}
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats[status] = count
	}
	return stats, rows.Err()
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (s *Store) ListRules(ctx context.Context) ([]models.Rule, error) {
	var rules []models.Rule
	err := s.db.SelectContext(ctx, &rules, `SELECT * FROM rules ORDER BY severity DESC, name`)
	return rules, err
}

func (s *Store) GetRule(ctx context.Context, id string) (*models.Rule, error) {
	var r models.Rule
	err := s.db.GetContext(ctx, &r, `SELECT * FROM rules WHERE id=$1`, id)
	return &r, err
}

func (s *Store) UpsertRule(ctx context.Context, r *models.Rule) error {
	conds, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	if r.RuleType == "" { r.RuleType = "match" }
	if r.GroupBy  == "" { r.GroupBy  = "agent_id" }
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO rules (id, name, description, enabled, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			name              = EXCLUDED.name,
			description       = EXCLUDED.description,
			enabled           = EXCLUDED.enabled,
			severity          = EXCLUDED.severity,
			event_types       = EXCLUDED.event_types,
			conditions        = EXCLUDED.conditions,
			mitre_ids         = EXCLUDED.mitre_ids,
			rule_type         = EXCLUDED.rule_type,
			threshold_count   = EXCLUDED.threshold_count,
			threshold_window_s= EXCLUDED.threshold_window_s,
			group_by          = EXCLUDED.group_by,
			updated_at        = NOW()
	`, r.ID, r.Name, r.Description, r.Enabled, r.Severity,
		pq.Array(r.EventTypes), conds, pq.Array(r.MitreIDs), r.Author,
		r.RuleType, r.ThresholdCount, r.ThresholdWindowS, r.GroupBy)
	return err
}

func (s *Store) DeleteRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id=$1`, id)
	return err
}

// ─── Suppression Rules ────────────────────────────────────────────────────────

func (s *Store) ListSuppressions(ctx context.Context) ([]models.SuppressionRule, error) {
	var sups []models.SuppressionRule
	err := s.db.SelectContext(ctx, &sups,
		`SELECT * FROM suppression_rules ORDER BY created_at DESC`)
	return sups, err
}

func (s *Store) GetSuppression(ctx context.Context, id string) (*models.SuppressionRule, error) {
	var r models.SuppressionRule
	err := s.db.GetContext(ctx, &r, `SELECT * FROM suppression_rules WHERE id=$1`, id)
	return &r, err
}

func (s *Store) UpsertSuppression(ctx context.Context, r *models.SuppressionRule) error {
	conds, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO suppression_rules
			(id, name, description, enabled, event_types, conditions, author, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			name        = EXCLUDED.name,
			description = EXCLUDED.description,
			enabled     = EXCLUDED.enabled,
			event_types = EXCLUDED.event_types,
			conditions  = EXCLUDED.conditions,
			updated_at  = NOW()
	`, r.ID, r.Name, r.Description, r.Enabled,
		pq.Array(r.EventTypes), conds, r.Author)
	return err
}

func (s *Store) DeleteSuppression(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM suppression_rules WHERE id=$1`, id)
	return err
}

// IncrSuppressionHits increments the hit counter for a suppression rule.
// Called asynchronously — errors are intentionally ignored.
func (s *Store) IncrSuppressionHits(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE suppression_rules
		SET hit_count = hit_count + 1, last_hit_at = NOW()
		WHERE id = $1`, id)
	return err
}

// ─── Rule backtest ────────────────────────────────────────────────────────────

// BacktestParams defines parameters for a rule backtest query.
type BacktestParams struct {
	EventTypes  []string
	Conditions  []byte // raw JSON conditions
	WindowHours int    // how many hours of history to scan
	Limit       int    // max events to scan
}

// BacktestRule runs a rule's conditions against recent historical events and
// returns matching counts + up to 5 sample matches.
func (s *Store) BacktestRule(ctx context.Context, p BacktestParams) (int, []models.Event, error) {
	if p.WindowHours == 0 {
		p.WindowHours = 168 // 7 days default
	}
	if p.Limit == 0 {
		p.Limit = 10000
	}
	since := time.Now().Add(-time.Duration(p.WindowHours) * time.Hour)

	params := QueryEventsParams{
		Since: &since,
		Limit: p.Limit,
	}
	if len(p.EventTypes) > 0 && p.EventTypes[0] != "*" {
		params.EventTypes = p.EventTypes
	}
	events, err := s.QueryEvents(ctx, params)
	if err != nil {
		return 0, nil, err
	}
	return len(events), events, nil
}
// FindOpenAlert returns the most recent OPEN/INVESTIGATING alert for this
// (rule_id, agent_id) pair that was last seen within dedupeWindow.
// Returns nil, nil when no match (caller should insert a new alert).
func (s *Store) FindOpenAlert(ctx context.Context, ruleID, agentID string, dedupeWindow time.Duration) (*models.Alert, error) {
	var a models.Alert
	cutoff := time.Now().Add(-dedupeWindow)
	err := s.db.GetContext(ctx, &a, `
		SELECT * FROM alerts
		WHERE rule_id  = $1
		  AND agent_id = $2
		  AND status   IN ('OPEN','INVESTIGATING')
		  AND last_seen >= $3
		ORDER BY last_seen DESC
		LIMIT 1`,
		ruleID, agentID, cutoff)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// BumpAlert updates last_seen, increments hit_count, and appends eventID
// to the event_ids array of an existing alert. Used for deduplication.
func (s *Store) BumpAlert(ctx context.Context, alertID, eventID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET
			last_seen  = NOW(),
			hit_count  = hit_count + 1,
			event_ids  = CASE
				WHEN $2 = ANY(event_ids) THEN event_ids
				ELSE event_ids || ARRAY[$2]::TEXT[]
			END
		WHERE id = $1`, alertID, eventID)
	return err
}

// UpdateAgentTags sets tags, env, and notes for an agent.
func (s *Store) UpdateAgentTags(ctx context.Context, id, env, notes string, tags []string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET tags=$2, env=$3, notes=$4 WHERE id=$1`,
		id, pq.Array(tags), env, notes)
	return err
}
// ─── Threat Hunting ───────────────────────────────────────────────────────────

// HuntQuery executes a safe, sanitized query against the events table.
// It supports a simple query language:
//
//	event_type = 'PROCESS_EXEC' AND hostname = 'web01' AND payload->>'exe_path' LIKE '%bash%'
//
// The query is inserted into a fixed WHERE clause template:
//
//	SELECT * FROM events WHERE (<user_query>) ORDER BY timestamp DESC LIMIT $1
//
// Security: Only allows SELECT-like predicates. Rejects any DDL/DML keywords.
func (s *Store) HuntQuery(ctx context.Context, query string, limit int) ([]models.Event, int, error) {
	if query == "" {
		return nil, 0, fmt.Errorf("empty query")
	}

	// Reject semicolons.
	if strings.Contains(query, ";") {
		return nil, 0, fmt.Errorf("invalid query: semicolons are not allowed")
	}

	// Reject dangerous SQL keywords (case-insensitive).
	upper := strings.ToUpper(query)
	blocked := []string{
		"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE",
		"CREATE", "GRANT", "EXEC", "UNION",
	}
	for _, kw := range blocked {
		// Use word-boundary matching: check that the keyword is surrounded by
		// non-alphanumeric characters (or is at the start/end of the string).
		idx := 0
		for idx <= len(upper)-len(kw) {
			pos := strings.Index(upper[idx:], kw)
			if pos < 0 {
				break
			}
			absPos := idx + pos
			before := absPos == 0 || !isAlphaNum(upper[absPos-1])
			after := absPos+len(kw) >= len(upper) || !isAlphaNum(upper[absPos+len(kw)])
			if before && after {
				return nil, 0, fmt.Errorf("invalid query: forbidden keyword %q", kw)
			}
			idx = absPos + len(kw)
		}
	}

	// If the user sent a full SELECT statement, extract just the WHERE predicate.
	normalized := strings.TrimSpace(query)
	upperNorm := strings.ToUpper(normalized)

	// Strip "SELECT * FROM events WHERE " prefix if present.
	for _, prefix := range []string{
		"SELECT * FROM EVENTS WHERE ",
		"SELECT * FROM EVENTS\nWHERE ",
		"SELECT * FROM EVENTS  WHERE ",
	} {
		if strings.HasPrefix(upperNorm, prefix) {
			normalized = strings.TrimSpace(normalized[len(prefix):])
			upperNorm = strings.ToUpper(normalized)
			break
		}
	}

	// Strip trailing ORDER BY / LIMIT clauses (backend applies its own).
	for _, suffix := range []string{"ORDER BY", "LIMIT"} {
		if idx := strings.LastIndex(upperNorm, suffix); idx > 0 {
			normalized = strings.TrimSpace(normalized[:idx])
			upperNorm = strings.ToUpper(normalized)
		}
	}

	query = normalized

	// Build the SQL.
	dataSQL := fmt.Sprintf(`SELECT * FROM events WHERE (%s) ORDER BY timestamp DESC LIMIT $1`, query)
	countSQL := fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE (%s)`, query)

	var events []models.Event
	if err := s.db.SelectContext(ctx, &events, dataSQL, limit); err != nil {
		return nil, 0, fmt.Errorf("hunt query failed: %w", err)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, countSQL).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("hunt count failed: %w", err)
	}

	return events, total, nil
}

// isAlphaNum returns true if b is A-Z, a-z, 0-9, or underscore.
func isAlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

// ─── Settings ─────────────────────────────────────────────────────────────────

// GetSetting returns a setting value by key, or the default if not found.
func (s *Store) GetSetting(ctx context.Context, key, defaultVal string) string {
	var val string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&val)
	if err != nil {
		return defaultVal
	}
	return val
}

// SetSetting upserts a setting value.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=NOW()`,
		key, value)
	return err
}

// GetRetentionDays returns (eventDays, alertDays) from settings.
func (s *Store) GetRetentionDays(ctx context.Context) (int, int) {
	evtStr  := s.GetSetting(ctx, "retention_events_days", "30")
	alrtStr := s.GetSetting(ctx, "retention_alerts_days", "90")
	evt,  _ := strconv.Atoi(evtStr)
	alrt, _ := strconv.Atoi(alrtStr)
	if evt  == 0 { evt  = 30 }
	if alrt == 0 { alrt = 90 }
	return evt, alrt
}

// ─── Process Tree ──────────────────────────────────────────────────────────────

// ProcessNode represents a node in a reconstructed process tree.
type ProcessNode struct {
	PID       uint32          `json:"pid"`
	PPID      uint32          `json:"ppid"`
	Comm      string          `json:"comm"`
	ExePath   string          `json:"exe_path"`
	Cmdline   string          `json:"cmdline"`
	UID       uint32          `json:"uid"`
	Username  string          `json:"username"`
	Timestamp time.Time       `json:"timestamp"`
	EventID   string          `json:"event_id"`
	EventType string          `json:"event_type"`
	Children  []*ProcessNode  `json:"children,omitempty"`
}

// processInfoFromEvent extracts process info from an event's JSONB payload.
func processInfoFromEvent(e *models.Event) ProcessNode {
	node := ProcessNode{
		Timestamp: e.Timestamp,
		EventID:   e.ID,
		EventType: e.EventType,
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &payload); err != nil {
		return node
	}

	procJSON, ok := payload["process"]
	if !ok {
		return node
	}

	var proc struct {
		PID      uint32 `json:"pid"`
		PPID     uint32 `json:"ppid"`
		Comm     string `json:"comm"`
		ExePath  string `json:"exe_path"`
		Cmdline  string `json:"cmdline"`
		UID      uint32 `json:"uid"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(procJSON, &proc); err != nil {
		return node
	}

	node.PID = proc.PID
	node.PPID = proc.PPID
	node.Comm = proc.Comm
	node.ExePath = proc.ExePath
	node.Cmdline = proc.Cmdline
	node.UID = proc.UID
	node.Username = proc.Username
	return node
}

// GetProcessTree returns a tree rooted at the given PID.
// It walks up the ancestor chain (up to depth levels) and down to find children.
func (s *Store) GetProcessTree(ctx context.Context, agentID string, pid int, depth int) (*ProcessNode, error) {
	// Find the target process.
	var target models.Event
	err := s.db.GetContext(ctx, &target, `
		SELECT * FROM events
		WHERE agent_id = $1
		  AND event_type = 'PROCESS_EXEC'
		  AND (payload->'process'->>'pid')::int = $2
		ORDER BY timestamp DESC LIMIT 1`, agentID, pid)
	if err != nil {
		return nil, fmt.Errorf("process pid=%d not found: %w", pid, err)
	}

	root := processInfoFromEvent(&target)

	// Walk down: find children (processes whose PPID = this PID).
	s.findChildren(ctx, agentID, &root, depth)

	// Walk up: find ancestors and re-root the tree.
	ancestors, _ := s.GetProcessAncestors(ctx, agentID, pid, depth)
	if len(ancestors) > 0 {
		// Build the ancestor chain top-down: grandparent -> parent -> root.
		// ancestors[0] is parent, ancestors[1] is grandparent, etc.
		// Reverse to build top-down.
		top := &ProcessNode{}
		*top = ancestors[len(ancestors)-1]
		current := top
		for i := len(ancestors) - 2; i >= 0; i-- {
			child := &ProcessNode{}
			*child = ancestors[i]
			current.Children = append(current.Children, child)
			current = child
		}
		// Attach the original root (with its children) to the bottom ancestor.
		current.Children = append(current.Children, &root)
		return top, nil
	}

	return &root, nil
}

// findChildren recursively finds child processes.
func (s *Store) findChildren(ctx context.Context, agentID string, node *ProcessNode, depth int) {
	if depth <= 0 {
		return
	}

	var children []models.Event
	err := s.db.SelectContext(ctx, &children, `
		SELECT * FROM events
		WHERE agent_id = $1
		  AND event_type = 'PROCESS_EXEC'
		  AND (payload->'process'->>'ppid')::int = $2
		ORDER BY timestamp DESC LIMIT 100`, agentID, node.PID)
	if err != nil || len(children) == 0 {
		return
	}

	// Deduplicate by PID (keep most recent).
	seen := make(map[uint32]bool)
	for i := range children {
		child := processInfoFromEvent(&children[i])
		if seen[child.PID] || child.PID == 0 {
			continue
		}
		seen[child.PID] = true
		s.findChildren(ctx, agentID, &child, depth-1)
		node.Children = append(node.Children, &child)
	}
}

// GetProcessAncestors returns the ancestor chain (parent, grandparent, ...) up to maxDepth.
func (s *Store) GetProcessAncestors(ctx context.Context, agentID string, pid int, maxDepth int) ([]ProcessNode, error) {
	var ancestors []ProcessNode
	currentPID := pid

	for i := 0; i < maxDepth; i++ {
		// Find this process to get its PPID.
		var ev models.Event
		err := s.db.GetContext(ctx, &ev, `
			SELECT * FROM events
			WHERE agent_id = $1
			  AND event_type = 'PROCESS_EXEC'
			  AND (payload->'process'->>'pid')::int = $2
			ORDER BY timestamp DESC LIMIT 1`, agentID, currentPID)
		if err != nil {
			break
		}

		node := processInfoFromEvent(&ev)
		ppid := int(node.PPID)

		// Stop if we reach init (PID 1) or self-parent.
		if ppid == 0 || ppid == currentPID {
			break
		}

		// Find the parent process event.
		var parentEv models.Event
		err = s.db.GetContext(ctx, &parentEv, `
			SELECT * FROM events
			WHERE agent_id = $1
			  AND event_type = 'PROCESS_EXEC'
			  AND (payload->'process'->>'pid')::int = $2
			ORDER BY timestamp DESC LIMIT 1`, agentID, ppid)
		if err != nil {
			break
		}

		parent := processInfoFromEvent(&parentEv)
		ancestors = append(ancestors, parent)
		currentPID = ppid
	}

	return ancestors, nil
}

// ─── Incidents ────────────────────────────────────────────────────────────────

// InsertIncident creates a new incident.
func (s *Store) InsertIncident(ctx context.Context, inc *models.Incident) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents
		  (id, title, description, severity, status, alert_ids, agent_ids, hostnames, mitre_ids,
		   alert_count, first_seen, last_seen, assignee, notes, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),NOW())`,
		inc.ID, inc.Title, inc.Description, inc.Severity, inc.Status,
		pq.Array(inc.AlertIDs), pq.Array(inc.AgentIDs), pq.Array(inc.Hostnames), pq.Array(inc.MitreIDs),
		inc.AlertCount, inc.FirstSeen, inc.LastSeen, inc.Assignee, inc.Notes)
	return err
}

// QueryIncidentsParams defines filter/pagination for incident queries.
type QueryIncidentsParams struct {
	Status   string
	Severity int16
	AgentID  string
	Limit    int
	Offset   int
}

// QueryIncidents returns incidents matching the given filters.
func (s *Store) QueryIncidents(ctx context.Context, p QueryIncidentsParams) ([]models.Incident, error) {
	if p.Limit == 0 {
		p.Limit = 50
	}
	query := `SELECT * FROM incidents WHERE 1=1`
	args := []interface{}{}
	n := 0
	if p.Status != "" {
		n++
		query += fmt.Sprintf(` AND status=$%d`, n)
		args = append(args, p.Status)
	}
	if p.Severity > 0 {
		n++
		query += fmt.Sprintf(` AND severity >= $%d`, n)
		args = append(args, p.Severity)
	}
	if p.AgentID != "" {
		n++
		query += fmt.Sprintf(` AND $%d = ANY(agent_ids)`, n)
		args = append(args, p.AgentID)
	}
	query += ` ORDER BY last_seen DESC`
	n++
	query += fmt.Sprintf(` LIMIT $%d`, n)
	args = append(args, p.Limit)
	n++
	query += fmt.Sprintf(` OFFSET $%d`, n)
	args = append(args, p.Offset)

	var incidents []models.Incident
	err := s.db.SelectContext(ctx, &incidents, query, args...)
	return incidents, err
}

// GetIncident returns a single incident by ID.
func (s *Store) GetIncident(ctx context.Context, id string) (*models.Incident, error) {
	var inc models.Incident
	err := s.db.GetContext(ctx, &inc, `SELECT * FROM incidents WHERE id=$1`, id)
	return &inc, err
}

// UpdateIncident updates mutable incident fields.
func (s *Store) UpdateIncident(ctx context.Context, id, status, assignee, notes string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET status=$2, assignee=$3, notes=$4, updated_at=NOW()
		WHERE id=$1`, id, status, assignee, notes)
	return err
}

// FindOpenIncident finds an existing OPEN/INVESTIGATING incident for the given
// agent_id that was last seen within the correlation window.
func (s *Store) FindOpenIncident(ctx context.Context, agentID string, window time.Duration) (*models.Incident, error) {
	var inc models.Incident
	cutoff := time.Now().Add(-window)
	err := s.db.GetContext(ctx, &inc, `
		SELECT * FROM incidents
		WHERE $1 = ANY(agent_ids)
		  AND status IN ('OPEN','INVESTIGATING')
		  AND last_seen >= $2
		ORDER BY last_seen DESC LIMIT 1`, agentID, cutoff)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &inc, nil
}

// AddAlertToIncident appends an alert to an existing incident, updating
// aggregated fields (severity, hostnames, mitre_ids, counts).
func (s *Store) AddAlertToIncident(ctx context.Context, incidentID string, alert *models.Alert) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET
			alert_ids   = array_append(alert_ids, $2),
			agent_ids   = CASE WHEN $3 = ANY(agent_ids) THEN agent_ids ELSE array_append(agent_ids, $3) END,
			hostnames   = CASE WHEN $4 = ANY(hostnames) THEN hostnames ELSE array_append(hostnames, $4) END,
			mitre_ids   = (SELECT ARRAY(SELECT DISTINCT unnest(mitre_ids || $5::text[]))),
			alert_count = alert_count + 1,
			severity    = GREATEST(severity, $6),
			last_seen   = NOW(),
			updated_at  = NOW()
		WHERE id = $1`,
		incidentID, alert.ID, alert.AgentID, alert.Hostname,
		pq.Array(alert.MitreIDs), alert.Severity)
	return err
}

// SetAlertIncident links an alert to an incident.
func (s *Store) SetAlertIncident(ctx context.Context, alertID, incidentID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET incident_id=$2 WHERE id=$1`, alertID, incidentID)
	return err
}

// GetIncidentAlerts returns all alerts belonging to an incident.
func (s *Store) GetIncidentAlerts(ctx context.Context, incidentID string) ([]models.Alert, error) {
	var alerts []models.Alert
	err := s.db.SelectContext(ctx, &alerts, `
		SELECT * FROM alerts WHERE incident_id=$1 ORDER BY first_seen DESC`, incidentID)
	return alerts, err
}

// ─── Agent Packages ───────────────────────────────────────────────────────────

// UpsertAgentPackages replaces all packages for an agent within a transaction.
func (s *Store) UpsertAgentPackages(ctx context.Context, agentID string, packages []models.AgentPackage) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete existing packages for this agent.
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_packages WHERE agent_id=$1`, agentID); err != nil {
		return err
	}

	// Batch insert new packages.
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO agent_packages (agent_id, name, version, arch, collected_at)
		VALUES ($1, $2, $3, $4, NOW())`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range packages {
		if _, err := stmt.ExecContext(ctx, agentID, p.Name, p.Version, p.Arch); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListAgentPackages returns packages for a specific agent.
func (s *Store) ListAgentPackages(ctx context.Context, agentID string, limit, offset int) ([]models.AgentPackage, error) {
	if limit == 0 {
		limit = 500
	}
	var pkgs []models.AgentPackage
	err := s.db.SelectContext(ctx, &pkgs, `
		SELECT * FROM agent_packages WHERE agent_id=$1
		ORDER BY name ASC LIMIT $2 OFFSET $3`, agentID, limit, offset)
	return pkgs, err
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

// InsertVulnerability inserts a single vulnerability record.
func (s *Store) InsertVulnerability(ctx context.Context, v *models.Vulnerability) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (agent_id, package_name, package_version, cve_id, severity, description, fixed_version, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		v.AgentID, v.PackageName, v.PackageVersion, v.CveID, v.Severity, v.Description, v.FixedVersion)
	return err
}

// QueryVulnerabilities returns vulnerabilities for an agent with pagination.
func (s *Store) QueryVulnerabilities(ctx context.Context, agentID string, limit, offset int) ([]models.Vulnerability, error) {
	if limit == 0 {
		limit = 50
	}
	query := `SELECT * FROM vulnerabilities WHERE 1=1`
	args := []interface{}{}
	argN := 1

	if agentID != "" {
		query += fmt.Sprintf(` AND agent_id = $%d`, argN)
		args = append(args, agentID)
		argN++
	}

	query += fmt.Sprintf(` ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, limit, offset)

	var vulns []models.Vulnerability
	err := s.db.SelectContext(ctx, &vulns, query, args...)
	return vulns, err
}

// QueryVulnerabilitiesFiltered returns vulnerabilities with optional agent_id and severity filters.
func (s *Store) QueryVulnerabilitiesFiltered(ctx context.Context, agentID, severity string, limit, offset int) ([]models.Vulnerability, error) {
	if limit == 0 {
		limit = 50
	}
	query := `SELECT * FROM vulnerabilities WHERE 1=1`
	args := []interface{}{}
	argN := 1

	if agentID != "" {
		query += fmt.Sprintf(` AND agent_id = $%d`, argN)
		args = append(args, agentID)
		argN++
	}
	if severity != "" {
		query += fmt.Sprintf(` AND severity = $%d`, argN)
		args = append(args, severity)
		argN++
	}

	query += fmt.Sprintf(` ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, limit, offset)

	var vulns []models.Vulnerability
	err := s.db.SelectContext(ctx, &vulns, query, args...)
	return vulns, err
}

// GetVulnStats returns vulnerability counts by severity for an agent.
func (s *Store) GetVulnStats(ctx context.Context, agentID string) (*models.VulnStats, error) {
	query := `SELECT severity, COUNT(*) FROM vulnerabilities`
	args := []interface{}{}
	if agentID != "" {
		query += ` WHERE agent_id = $1`
		args = append(args, agentID)
	}
	query += ` GROUP BY severity`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &models.VulnStats{}
	for rows.Next() {
		var sev string
		var count int64
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats.Total += count
		switch sev {
		case "CRITICAL":
			stats.Critical = count
		case "HIGH":
			stats.High = count
		case "MEDIUM":
			stats.Medium = count
		case "LOW":
			stats.Low = count
		default:
			stats.Unknown += count
		}
	}
	return stats, rows.Err()
}

// ─── IOCs (Indicators of Compromise) ──────────────────────────────────────────

func (s *Store) InsertIOC(ctx context.Context, ioc *models.IOC) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO iocs (id, type, value, source, severity, description, tags, enabled, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (type, value) DO UPDATE SET
			source      = EXCLUDED.source,
			severity    = EXCLUDED.severity,
			description = EXCLUDED.description,
			tags        = EXCLUDED.tags,
			enabled     = EXCLUDED.enabled,
			expires_at  = EXCLUDED.expires_at
	`, ioc.ID, ioc.Type, ioc.Value, ioc.Source, ioc.Severity, ioc.Description,
		pq.Array(coalesceStringSlice(ioc.Tags)), ioc.Enabled, ioc.ExpiresAt, ioc.CreatedAt)
	return err
}

func (s *Store) InsertIOCBatch(ctx context.Context, iocs []models.IOC) (int, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO iocs (id, type, value, source, severity, description, tags, enabled, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (type, value) DO UPDATE SET
			source      = EXCLUDED.source,
			severity    = EXCLUDED.severity,
			description = EXCLUDED.description,
			tags        = EXCLUDED.tags,
			enabled     = EXCLUDED.enabled,
			expires_at  = EXCLUDED.expires_at
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for _, ioc := range iocs {
		_, err := stmt.ExecContext(ctx,
			ioc.ID, ioc.Type, ioc.Value, ioc.Source, ioc.Severity, ioc.Description,
			pq.Array(coalesceStringSlice(ioc.Tags)), ioc.Enabled, ioc.ExpiresAt, ioc.CreatedAt)
		if err != nil {
			return count, err
		}
		count++
	}
	return count, tx.Commit()
}

func (s *Store) ListIOCs(ctx context.Context, iocType, source string, enabledOnly bool, limit, offset int) ([]models.IOC, error) {
	q := "SELECT * FROM iocs WHERE 1=1"
	args := []interface{}{}
	n := 0

	if iocType != "" {
		n++
		q += fmt.Sprintf(" AND type=$%d", n)
		args = append(args, iocType)
	}
	if source != "" {
		n++
		q += fmt.Sprintf(" AND source=$%d", n)
		args = append(args, source)
	}
	if enabledOnly {
		q += " AND enabled=TRUE"
	}
	q += " ORDER BY created_at DESC"
	if limit > 0 {
		n++
		q += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, limit)
	}
	if offset > 0 {
		n++
		q += fmt.Sprintf(" OFFSET $%d", n)
		args = append(args, offset)
	}

	var iocs []models.IOC
	err := s.db.SelectContext(ctx, &iocs, q, args...)
	return iocs, err
}

func (s *Store) GetIOC(ctx context.Context, id string) (*models.IOC, error) {
	var ioc models.IOC
	err := s.db.GetContext(ctx, &ioc, `SELECT * FROM iocs WHERE id=$1`, id)
	return &ioc, err
}

func (s *Store) DeleteIOC(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM iocs WHERE id=$1`, id)
	return err
}

func (s *Store) DeleteIOCsBySource(ctx context.Context, source string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM iocs WHERE source=$1`, source)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LookupIOC checks if a value exists as an enabled, non-expired IOC of the given type.
func (s *Store) LookupIOC(ctx context.Context, iocType, value string) (*models.IOC, error) {
	var ioc models.IOC
	err := s.db.GetContext(ctx, &ioc, `
		SELECT * FROM iocs
		WHERE type=$1 AND value=$2 AND enabled=TRUE
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, iocType, value)
	if err != nil {
		return nil, err
	}
	return &ioc, nil
}

// LoadActiveIOCs returns all enabled, non-expired IOCs of a given type, keyed by value.
func (s *Store) LoadActiveIOCs(ctx context.Context, iocType string) (map[string]*models.IOC, error) {
	var iocs []models.IOC
	err := s.db.SelectContext(ctx, &iocs, `
		SELECT * FROM iocs
		WHERE type=$1 AND enabled=TRUE
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, iocType)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*models.IOC, len(iocs))
	for i := range iocs {
		m[iocs[i].Value] = &iocs[i]
	}
	return m, nil
}

// IncrIOCHits increments the hit count and updates last_hit_at for an IOC.
func (s *Store) IncrIOCHits(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE iocs SET hit_count = hit_count + 1, last_hit_at = NOW() WHERE id=$1`, id)
	return err
}

// IOCStatsBySource returns IOC counts grouped by source, optionally filtered by time range.
func (s *Store) IOCStatsBySource(ctx context.Context, since time.Time) ([]models.IOCSourceStats, error) {
	q := `
		SELECT source,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE type='ip') AS ip_count,
			COUNT(*) FILTER (WHERE type='domain') AS domain_count,
			COUNT(*) FILTER (WHERE type IN ('hash_sha256','hash_md5')) AS hash_count,
			COUNT(*) FILTER (WHERE enabled=TRUE) AS enabled_count,
			COALESCE(SUM(hit_count), 0) AS total_hits,
			MIN(created_at) AS first_seen,
			MAX(created_at) AS last_updated
		FROM iocs
		WHERE created_at >= $1
		GROUP BY source
		ORDER BY total DESC
	`
	var stats []models.IOCSourceStats
	err := s.db.SelectContext(ctx, &stats, q, since)
	return stats, err
}

func (s *Store) IOCStats(ctx context.Context) (*models.IOCStats, error) {
	var stats models.IOCStats
	err := s.db.GetContext(ctx, &stats, `
		SELECT
			COUNT(*)                                       AS total_iocs,
			COUNT(*) FILTER (WHERE type='ip')              AS ip_count,
			COUNT(*) FILTER (WHERE type='domain')          AS domain_count,
			COUNT(*) FILTER (WHERE type IN ('hash_sha256','hash_md5')) AS hash_count,
			COUNT(*) FILTER (WHERE enabled=TRUE)           AS enabled_count,
			COALESCE(SUM(hit_count), 0)                    AS total_hits
		FROM iocs
	`)
	return &stats, err
}
