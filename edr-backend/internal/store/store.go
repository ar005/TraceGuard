// internal/store/store.go
// Repository layer — all database queries live here.

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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
