// internal/store/store.go
// Repository layer — all database queries live here.

package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/youredr/edr-backend/internal/models"
)

// Store wraps the database connection and provides typed query methods.
type Store struct {
	db     *sqlx.DB
	readDB *sqlx.DB // optional read replica; nil → use primary
}

func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// SetReadReplica configures an optional read replica. Once set, all read-heavy
// queries route to it; writes always go to the primary db.
func (s *Store) SetReadReplica(rdb *sqlx.DB) {
	s.readDB = rdb
}

// rdb returns the read replica if configured, otherwise the primary DB.
func (s *Store) rdb() *sqlx.DB {
	if s.readDB != nil {
		return s.readDB
	}
	return s.db
}

// DB returns the underlying sqlx.DB, used by the migration package.
func (s *Store) DB() *sqlx.DB {
	return s.db
}

// ─── Agents ───────────────────────────────────────────────────────────────────

func (s *Store) UpsertAgent(ctx context.Context, a *models.Agent) error {
	winCfg := a.WinEventConfig
	if len(winCfg) == 0 {
		winCfg = json.RawMessage(`{}`)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen, is_online, config_ver, tags, env, notes, winevent_config)
		VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW(),TRUE,$7,$8,$9,$10,$11)
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
			notes = CASE WHEN EXCLUDED.notes != '' THEN EXCLUDED.notes ELSE agents.notes END,
			winevent_config = CASE WHEN EXCLUDED.winevent_config != '{}'::jsonb THEN EXCLUDED.winevent_config ELSE agents.winevent_config END
	`, a.ID, a.Hostname, a.OS, a.OSVersion, a.IP, a.AgentVer, a.ConfigVer,
		pq.Array(coalesceStringSlice(a.Tags)), a.Env, a.Notes, winCfg)
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
	err := s.rdb().GetContext(ctx, &a, `SELECT * FROM agents WHERE id=$1`, id)
	return &a, err
}

func (s *Store) ListAgents(ctx context.Context) ([]models.Agent, error) {
	var agents []models.Agent
	err := s.rdb().SelectContext(ctx, &agents, `SELECT * FROM agents ORDER BY last_seen DESC`)
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
	err := s.rdb().SelectContext(ctx, &events, query, args...)
	return events, err
}

func (s *Store) GetEvent(ctx context.Context, id string) (*models.Event, error) {
	var e models.Event
	err := s.rdb().GetContext(ctx, &e, `SELECT * FROM events WHERE id=$1`, id)
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

// TimelinePoint is one hourly bucket of event counts.
type TimelinePoint struct {
	Hour  string `db:"hour"  json:"hour"`
	Count int64  `db:"count" json:"count"`
}

// EventsTimeline returns per-hour event counts from since to now.
func (s *Store) EventsTimeline(ctx context.Context, since time.Time) ([]TimelinePoint, error) {
	var pts []TimelinePoint
	err := s.rdb().SelectContext(ctx, &pts, `
		SELECT
			to_char(date_trunc('hour', timestamp AT TIME ZONE 'UTC'),
				'YYYY-MM-DD"T"HH24:00:00"Z"') AS hour,
			COUNT(*) AS count
		FROM events
		WHERE timestamp >= $1
		GROUP BY date_trunc('hour', timestamp AT TIME ZONE 'UTC')
		ORDER BY 1 ASC
	`, since)
	return pts, err
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
		  (id, title, description, severity, status, rule_id, rule_name, mitre_ids, event_ids, agent_id, hostname, user_uid, source_types, first_seen, last_seen, hit_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW(),1)
		ON CONFLICT (id) DO UPDATE SET
			last_seen    = NOW(),
			hit_count    = alerts.hit_count + 1,
			event_ids    = alerts.event_ids || EXCLUDED.event_ids,
			source_types = (SELECT array_agg(DISTINCT x) FROM unnest(alerts.source_types || EXCLUDED.source_types) x),
			status       = CASE WHEN alerts.status='CLOSED' THEN 'OPEN' ELSE alerts.status END
	`, a.ID, a.Title, a.Description, a.Severity, a.Status,
		a.RuleID, a.RuleName, pq.Array(a.MitreIDs), pq.Array(a.EventIDs),
		a.AgentID, a.Hostname, a.UserUID, pq.Array(a.SourceTypes))
	return err
}

// QueryAlertsParams defines filter/pagination for alert queries.
type QueryAlertsParams struct {
	AgentID  string
	Status   string
	Severity int16
	RuleID   string
	Search   string
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
	if p.Search != "" {
		query += fmt.Sprintf(` AND (title ILIKE $%d OR rule_name ILIKE $%d OR hostname ILIKE $%d)`, argN, argN, argN)
		args = append(args, "%"+p.Search+"%")
		argN++
	}

	query += fmt.Sprintf(` ORDER BY first_seen DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, p.Limit, p.Offset)

	var alerts []models.Alert
	err := s.rdb().SelectContext(ctx, &alerts, query, args...)
	return alerts, err
}

func (s *Store) GetAlert(ctx context.Context, id string) (*models.Alert, error) {
	var a models.Alert
	err := s.rdb().GetContext(ctx, &a, `SELECT * FROM alerts WHERE id=$1`, id)
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
		err = s.rdb().SelectContext(ctx, &events,
			`SELECT * FROM events WHERE alert_id=$1 ORDER BY timestamp DESC LIMIT 500`,
			alertID)
		return events, err
	}

	// Fetch by event IDs first (exact match), then also by alert_id, union them.
	var byID, byAlertID []models.Event
	if err2 := s.rdb().SelectContext(ctx, &byID,
		`SELECT * FROM events WHERE id = ANY($1) ORDER BY timestamp DESC`,
		pq.Array(eventIDs)); err2 != nil {
		return nil, err2
	}
	if err2 := s.rdb().SelectContext(ctx, &byAlertID,
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

func (s *Store) UpdateAlertTriage(ctx context.Context, id, verdict string, score int16, notes string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET triage_verdict=$2, triage_score=$3, triage_notes=$4, triage_at=NOW() WHERE id=$1`,
		id, verdict, score, notes)
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
	err := s.rdb().SelectContext(ctx, &rules, `SELECT * FROM rules ORDER BY severity DESC, name`)
	return rules, err
}

func (s *Store) GetRule(ctx context.Context, id string) (*models.Rule, error) {
	var r models.Rule
	err := s.rdb().GetContext(ctx, &r, `SELECT * FROM rules WHERE id=$1`, id)
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
	err := s.rdb().SelectContext(ctx, &sups,
		`SELECT * FROM suppression_rules ORDER BY created_at DESC`)
	return sups, err
}

func (s *Store) GetSuppression(ctx context.Context, id string) (*models.SuppressionRule, error) {
	var r models.SuppressionRule
	err := s.rdb().GetContext(ctx, &r, `SELECT * FROM suppression_rules WHERE id=$1`, id)
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
	err := s.rdb().GetContext(ctx, &a, `
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

// UpdateAgentWinEventConfig sets the Windows Event Log channel configuration for an agent.
func (s *Store) UpdateAgentWinEventConfig(ctx context.Context, id string, config json.RawMessage) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET winevent_config=$2 WHERE id=$1`,
		id, config)
	return err
}

// GetAgentWinEventConfig returns the Windows Event Log configuration for an agent.
func (s *Store) GetAgentWinEventConfig(ctx context.Context, id string) (json.RawMessage, error) {
	var config json.RawMessage
	err := s.rdb().GetContext(ctx, &config,
		`SELECT winevent_config FROM agents WHERE id=$1`, id)
	return config, err
}
// ─── Threat Hunting ───────────────────────────────────────────────────────────

// allowedHuntColumns is the whitelist of columns users may filter on.
// JSONB paths like payload->>'exe_path' are handled separately.
var allowedHuntColumns = map[string]bool{
	"id":          true,
	"agent_id":    true,
	"hostname":    true,
	"event_type":  true,
	"timestamp":   true,
	"received_at": true,
	"severity":    true,
	"rule_id":     true,
	"alert_id":    true,
}

// allowedHuntOps is the whitelist of comparison operators.
var allowedHuntOps = map[string]bool{
	"=": true, "!=": true, "<>": true,
	"<": true, ">": true, "<=": true, ">=": true,
	"LIKE": true, "ILIKE": true, "NOT LIKE": true, "NOT ILIKE": true,
	"IS NULL": true, "IS NOT NULL": true,
	"IN": true, "NOT IN": true,
}

// huntFilter represents a single parsed predicate.
type huntFilter struct {
	Column   string   // e.g. "hostname" or "payload->>'exe_path'"
	Op       string   // e.g. "=", "LIKE", "IS NULL", "IN"
	Values   []string // bound parameter values (empty for IS NULL / IS NOT NULL)
	Negate   bool     // NOT prefix
	JSONPath string   // raw JSONB path for payload fields
}

// HuntQuery executes a parameterized query against the events table.
// It parses a structured filter language into safe, parameterized SQL.
//
// Supported syntax (filters joined by AND/OR):
//
//	event_type = 'PROCESS_EXEC' AND hostname = 'web01'
//	payload->>'exe_path' LIKE '%bash%'
//	severity >= 3
//	event_type IN ('PROCESS_EXEC', 'CMD_EXEC')
//	hostname IS NOT NULL
//
// All user-supplied values are parameterized — no raw SQL is ever interpolated.
func (s *Store) HuntQuery(ctx context.Context, query string, limit int) ([]models.Event, int, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, 0, fmt.Errorf("empty query")
	}

	// Strip "SELECT * FROM events WHERE" prefix if the user included it.
	upperQ := strings.ToUpper(query)
	for _, prefix := range []string{
		"SELECT * FROM EVENTS WHERE ",
		"SELECT * FROM EVENTS\nWHERE ",
	} {
		if strings.HasPrefix(upperQ, prefix) {
			query = strings.TrimSpace(query[len(prefix):])
			break
		}
	}

	// Strip trailing ORDER BY / LIMIT (we apply our own).
	upperQ = strings.ToUpper(query)
	for _, kw := range []string{" ORDER BY", " LIMIT"} {
		if idx := strings.LastIndex(upperQ, kw); idx > 0 {
			query = strings.TrimSpace(query[:idx])
			upperQ = strings.ToUpper(query)
		}
	}

	whereClause, args, err := parseHuntQuery(query)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid query: %w", err)
	}

	limitParam := len(args) + 1
	dataSQL := fmt.Sprintf(`SELECT * FROM events WHERE %s ORDER BY timestamp DESC LIMIT $%d`, whereClause, limitParam)
	countSQL := fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, whereClause)

	allArgs := append(args, limit)

	var events []models.Event
	if err := s.rdb().SelectContext(ctx, &events, dataSQL, allArgs...); err != nil {
		return nil, 0, fmt.Errorf("hunt query failed: %w", err)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("hunt count failed: %w", err)
	}

	return events, total, nil
}

// parseHuntQuery parses the user query string into parameterized SQL.
// Returns the WHERE clause with $N placeholders and the corresponding args slice.
func parseHuntQuery(query string) (string, []interface{}, error) {
	// Reject obviously dangerous characters.
	if strings.Contains(query, ";") {
		return "", nil, fmt.Errorf("semicolons are not allowed")
	}
	if strings.Contains(query, "--") {
		return "", nil, fmt.Errorf("SQL comments are not allowed")
	}
	if strings.Contains(query, "/*") {
		return "", nil, fmt.Errorf("SQL comments are not allowed")
	}

	// Split on AND/OR while preserving the conjunction.
	parts, conjunctions := splitOnConjunctions(query)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("no filter conditions found")
	}

	var clauses []string
	var args []interface{}
	paramIdx := 1

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		clause, partArgs, nextIdx, err := parseFilterPart(part, paramIdx)
		if err != nil {
			return "", nil, err
		}
		clauses = append(clauses, clause)
		args = append(args, partArgs...)
		paramIdx = nextIdx
	}

	// Rebuild with conjunctions.
	var sb strings.Builder
	for i, clause := range clauses {
		if i > 0 {
			sb.WriteString(" ")
			if i-1 < len(conjunctions) {
				sb.WriteString(conjunctions[i-1])
			} else {
				sb.WriteString("AND")
			}
			sb.WriteString(" ")
		}
		sb.WriteString(clause)
	}

	return sb.String(), args, nil
}

// splitOnConjunctions splits a query on AND/OR keywords (not inside quotes).
func splitOnConjunctions(query string) ([]string, []string) {
	var parts []string
	var conjunctions []string

	upper := strings.ToUpper(query)
	inQuote := false
	quoteChar := byte(0)
	parenDepth := 0
	start := 0

	for i := 0; i < len(query); i++ {
		ch := query[i]
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			}
			continue
		}
		if ch == '\'' {
			inQuote = true
			quoteChar = ch
			continue
		}
		if ch == '(' {
			parenDepth++
			continue
		}
		if ch == ')' {
			parenDepth--
			continue
		}
		if parenDepth > 0 {
			continue
		}

		// Check for AND / OR at word boundaries.
		for _, conj := range []string{" AND ", " OR "} {
			if i+len(conj) <= len(upper) && upper[i:i+len(conj)] == conj {
				parts = append(parts, query[start:i])
				conjunctions = append(conjunctions, strings.TrimSpace(conj))
				i += len(conj) - 1
				start = i + 1
				break
			}
		}
	}
	parts = append(parts, query[start:])
	return parts, conjunctions
}

// parseFilterPart parses a single filter expression like "hostname = 'web01'"
// and returns parameterized SQL.
func parseFilterPart(part string, paramIdx int) (string, []interface{}, int, error) {
	part = strings.TrimSpace(part)

	// Handle parenthesized groups: (expr)
	if strings.HasPrefix(part, "(") && strings.HasSuffix(part, ")") {
		inner := part[1 : len(part)-1]
		clause, args, nextIdx, err := parseFilterGroup(inner, paramIdx)
		if err != nil {
			return "", nil, 0, err
		}
		return "(" + clause + ")", args, nextIdx, nil
	}

	upperPart := strings.ToUpper(strings.TrimSpace(part))

	// IS NULL / IS NOT NULL
	if strings.HasSuffix(upperPart, " IS NOT NULL") {
		col := strings.TrimSpace(part[:len(part)-len(" IS NOT NULL")])
		safeCol, err := validateColumn(col)
		if err != nil {
			return "", nil, 0, err
		}
		return safeCol + " IS NOT NULL", nil, paramIdx, nil
	}
	if strings.HasSuffix(upperPart, " IS NULL") {
		col := strings.TrimSpace(part[:len(part)-len(" IS NULL")])
		safeCol, err := validateColumn(col)
		if err != nil {
			return "", nil, 0, err
		}
		return safeCol + " IS NULL", nil, paramIdx, nil
	}

	// IN / NOT IN: column IN ('val1', 'val2')
	for _, inOp := range []string{" NOT IN ", " IN "} {
		if idx := strings.Index(upperPart, inOp); idx > 0 {
			col := strings.TrimSpace(part[:idx])
			safeCol, err := validateColumn(col)
			if err != nil {
				return "", nil, 0, err
			}
			valsPart := strings.TrimSpace(part[idx+len(inOp):])
			vals, err := parseINValues(valsPart)
			if err != nil {
				return "", nil, 0, err
			}
			var placeholders []string
			var args []interface{}
			for _, v := range vals {
				placeholders = append(placeholders, fmt.Sprintf("$%d", paramIdx))
				args = append(args, v)
				paramIdx++
			}
			opStr := strings.TrimSpace(inOp)
			return fmt.Sprintf("%s %s (%s)", safeCol, opStr, strings.Join(placeholders, ", ")), args, paramIdx, nil
		}
	}

	// Standard comparison: column OP 'value'
	// Try multi-char ops first, then single-char.
	for _, op := range []string{"NOT ILIKE", "NOT LIKE", "ILIKE", "LIKE", "!=", "<>", "<=", ">=", "=", "<", ">"} {
		opUpper := strings.ToUpper(op)
		var idx int
		if len(op) > 1 && (op[0] >= 'A' && op[0] <= 'Z' || op[0] >= 'a' && op[0] <= 'z') {
			// Word operators: need space boundaries.
			search := " " + opUpper + " "
			idx = strings.Index(upperPart, search)
			if idx >= 0 {
				col := strings.TrimSpace(part[:idx])
				val := strings.TrimSpace(part[idx+len(search):])
				return buildComparison(col, op, val, paramIdx)
			}
		} else {
			idx = strings.Index(part, op)
			if idx > 0 {
				col := strings.TrimSpace(part[:idx])
				val := strings.TrimSpace(part[idx+len(op):])
				return buildComparison(col, op, val, paramIdx)
			}
		}
	}

	return "", nil, 0, fmt.Errorf("cannot parse filter: %q", part)
}

// parseFilterGroup handles inner content of parenthesized groups.
func parseFilterGroup(inner string, paramIdx int) (string, []interface{}, int, error) {
	parts, conjunctions := splitOnConjunctions(inner)
	var clauses []string
	var allArgs []interface{}

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		clause, args, nextIdx, err := parseFilterPart(p, paramIdx)
		if err != nil {
			return "", nil, 0, err
		}
		clauses = append(clauses, clause)
		allArgs = append(allArgs, args...)
		paramIdx = nextIdx
	}

	var sb strings.Builder
	for i, clause := range clauses {
		if i > 0 {
			sb.WriteString(" ")
			if i-1 < len(conjunctions) {
				sb.WriteString(conjunctions[i-1])
			} else {
				sb.WriteString("AND")
			}
			sb.WriteString(" ")
		}
		sb.WriteString(clause)
	}
	return sb.String(), allArgs, paramIdx, nil
}

// buildComparison builds a parameterized comparison clause.
func buildComparison(col, op, rawVal string, paramIdx int) (string, []interface{}, int, error) {
	safeCol, err := validateColumn(col)
	if err != nil {
		return "", nil, 0, err
	}
	val := stripQuotes(rawVal)
	clause := fmt.Sprintf("%s %s $%d", safeCol, op, paramIdx)
	return clause, []interface{}{val}, paramIdx + 1, nil
}

// validateColumn checks that a column reference is allowed.
// Supports plain columns and payload JSONB paths like payload->>'field'.
func validateColumn(col string) (string, error) {
	col = strings.TrimSpace(col)
	lower := strings.ToLower(col)

	// Allow payload JSONB access: payload->>'key' or payload->'obj'->>'key'
	if strings.HasPrefix(lower, "payload") {
		return validateJSONBPath(col)
	}

	if !allowedHuntColumns[lower] {
		return "", fmt.Errorf("unknown column: %q (allowed: %s)", col, huntColumnList())
	}
	return lower, nil
}

// validateJSONBPath validates a JSONB access path like payload->>'exe_path'
// or payload->'process'->>'name'. Only allows alphanumeric keys.
func validateJSONBPath(path string) (string, error) {
	// Must start with "payload"
	rest := strings.TrimSpace(path[len("payload"):])

	var result strings.Builder
	result.WriteString("payload")

	for len(rest) > 0 {
		// Expect ->> or ->
		if strings.HasPrefix(rest, "->>") {
			result.WriteString("->>")
			rest = rest[3:]
		} else if strings.HasPrefix(rest, "->") {
			result.WriteString("->")
			rest = rest[2:]
		} else {
			return "", fmt.Errorf("invalid JSONB path: %q", path)
		}

		rest = strings.TrimSpace(rest)

		// Expect 'key' (quoted) or unquoted alphanumeric key.
		if len(rest) > 0 && rest[0] == '\'' {
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				return "", fmt.Errorf("unterminated JSONB key in: %q", path)
			}
			key := rest[1 : end+1]
			if !isAlphaNumDotUnderscore(key) {
				return "", fmt.Errorf("invalid JSONB key: %q", key)
			}
			result.WriteString("'")
			result.WriteString(key)
			result.WriteString("'")
			rest = rest[end+2:]
		} else {
			// Unquoted key: read until space, -, or end.
			end := 0
			for end < len(rest) && rest[end] != ' ' && rest[end] != '-' {
				end++
			}
			if end == 0 {
				return "", fmt.Errorf("empty JSONB key in: %q", path)
			}
			key := rest[:end]
			if !isAlphaNumDotUnderscore(key) {
				return "", fmt.Errorf("invalid JSONB key: %q", key)
			}
			result.WriteString("'")
			result.WriteString(key)
			result.WriteString("'")
			rest = rest[end:]
		}

		rest = strings.TrimSpace(rest)
	}

	return result.String(), nil
}

// parseINValues parses ('val1', 'val2', ...) into a slice of strings.
func parseINValues(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return nil, fmt.Errorf("IN values must be enclosed in parentheses")
	}
	inner := s[1 : len(s)-1]
	parts := strings.Split(inner, ",")
	var vals []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		vals = append(vals, stripQuotes(p))
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("IN clause requires at least one value")
	}
	return vals, nil
}

// stripQuotes removes surrounding single quotes from a value.
func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

// isAlphaNumDotUnderscore checks a string contains only safe identifier characters.
func isAlphaNumDotUnderscore(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
			return false
		}
	}
	return len(s) > 0
}

// huntColumnList returns a comma-separated list of allowed columns for error messages.
func huntColumnList() string {
	cols := make([]string, 0, len(allowedHuntColumns))
	for c := range allowedHuntColumns {
		cols = append(cols, c)
	}
	return strings.Join(cols, ", ")
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

// SetSecretSetting encrypts a value with AES-GCM before storing it.
// The encryption key is derived from EDR_JWT_SECRET.
func (s *Store) SetSecretSetting(ctx context.Context, key, plaintext string) error {
	encrypted, err := encryptAESGCM(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt setting: %w", err)
	}
	return s.SetSetting(ctx, key, "enc:"+encrypted)
}

// GetSecretSetting retrieves and decrypts an AES-GCM encrypted setting.
// Falls back to reading plaintext for backward compatibility with existing values.
func (s *Store) GetSecretSetting(ctx context.Context, key, defaultVal string) string {
	raw := s.GetSetting(ctx, key, "")
	if raw == "" {
		return defaultVal
	}
	if strings.HasPrefix(raw, "enc:") {
		decrypted, err := decryptAESGCM(raw[4:])
		if err != nil {
			return defaultVal
		}
		return decrypted
	}
	// Backward-compat: plaintext value from before encryption was added.
	return raw
}

// deriveKey produces a 32-byte AES key from EDR_JWT_SECRET via SHA-256.
func deriveKey() []byte {
	secret := os.Getenv("EDR_JWT_SECRET")
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func encryptAESGCM(plaintext string) (string, error) {
	block, err := aes.NewCipher(deriveKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAESGCM(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
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
	err := s.rdb().GetContext(ctx, &target, `
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
	err := s.rdb().SelectContext(ctx, &children, `
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
		err := s.rdb().GetContext(ctx, &ev, `
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
		err = s.rdb().GetContext(ctx, &parentEv, `
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
		   user_uids, src_ips, source_types, alert_count, first_seen, last_seen, assignee, notes, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW(),NOW())`,
		inc.ID, inc.Title, inc.Description, inc.Severity, inc.Status,
		pq.Array(inc.AlertIDs), pq.Array(inc.AgentIDs), pq.Array(inc.Hostnames), pq.Array(inc.MitreIDs),
		pq.Array(inc.UserUIDs), pq.Array(inc.SrcIPs), pq.Array(inc.SourceTypes),
		inc.AlertCount, inc.FirstSeen, inc.LastSeen, inc.Assignee, inc.Notes)
	return err
}

// QueryIncidentsParams defines filter/pagination for incident queries.
type QueryIncidentsParams struct {
	Search   string
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
	if p.Search != "" {
		n++
		query += fmt.Sprintf(` AND (title ILIKE $%d OR description ILIKE $%d)`, n, n)
		args = append(args, "%"+p.Search+"%")
	}
	query += ` ORDER BY last_seen DESC`
	n++
	query += fmt.Sprintf(` LIMIT $%d`, n)
	args = append(args, p.Limit)
	n++
	query += fmt.Sprintf(` OFFSET $%d`, n)
	args = append(args, p.Offset)

	var incidents []models.Incident
	err := s.rdb().SelectContext(ctx, &incidents, query, args...)
	return incidents, err
}

// GetIncident returns a single incident by ID.
func (s *Store) GetIncident(ctx context.Context, id string) (*models.Incident, error) {
	var inc models.Incident
	err := s.rdb().GetContext(ctx, &inc, `SELECT * FROM incidents WHERE id=$1`, id)
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
	err := s.rdb().GetContext(ctx, &inc, `
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

// FindOpenIncidentXdr looks up an open incident matching by user_uid or src_ip
// in addition to agent_id. Used for cross-source incident correlation.
func (s *Store) FindOpenIncidentXdr(ctx context.Context, agentID, userUID, srcIP string, window time.Duration) (*models.Incident, error) {
	var inc models.Incident
	cutoff := time.Now().Add(-window)
	err := s.rdb().GetContext(ctx, &inc, `
		SELECT * FROM incidents
		WHERE status IN ('OPEN','INVESTIGATING')
		  AND last_seen >= $4
		  AND (
		      ($1 != '' AND $1 = ANY(agent_ids))
		   OR ($2 != '' AND $2 = ANY(user_uids))
		   OR ($3 != '' AND $3::inet = ANY(src_ips))
		  )
		ORDER BY last_seen DESC LIMIT 1`, agentID, userUID, srcIP, cutoff)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &inc, nil
}

// AddAlertToIncidentXdr extends AddAlertToIncident with XDR cross-source fields.
func (s *Store) AddAlertToIncidentXdr(ctx context.Context, incidentID string, alert *models.Alert, userUID, srcIP, sourceType string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET
			alert_ids    = array_append(alert_ids, $2),
			agent_ids    = CASE WHEN $3 != '' AND NOT ($3 = ANY(agent_ids)) THEN array_append(agent_ids, $3) ELSE agent_ids END,
			hostnames    = CASE WHEN $4 != '' AND NOT ($4 = ANY(hostnames)) THEN array_append(hostnames, $4) ELSE hostnames END,
			user_uids    = CASE WHEN $5 != '' AND NOT ($5 = ANY(user_uids)) THEN array_append(user_uids, $5) ELSE user_uids END,
			src_ips      = CASE WHEN $6 != '' AND NOT ($6::text = ANY(src_ips::text[])) THEN array_append(src_ips, $6::inet) ELSE src_ips END,
			source_types = CASE WHEN $7 != '' AND NOT ($7 = ANY(source_types)) THEN array_append(source_types, $7) ELSE source_types END,
			mitre_ids    = (SELECT ARRAY(SELECT DISTINCT unnest(mitre_ids || $8::text[]))),
			alert_count  = alert_count + 1,
			severity     = GREATEST(severity, $9),
			last_seen    = NOW(),
			updated_at   = NOW()
		WHERE id = $1`,
		incidentID, alert.ID, alert.AgentID, alert.Hostname,
		userUID, srcIP, sourceType,
		pq.Array(alert.MitreIDs), alert.Severity)
	return err
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
	err := s.rdb().SelectContext(ctx, &alerts, `
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
	err := s.rdb().SelectContext(ctx, &pkgs, `
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
	err := s.rdb().SelectContext(ctx, &vulns, query, args...)
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
	err := s.rdb().SelectContext(ctx, &vulns, query, args...)
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

func (s *Store) ListIOCs(ctx context.Context, iocType, source, search string, enabledOnly bool, limit, offset int) ([]models.IOC, error) {
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
	if search != "" {
		n++
		q += fmt.Sprintf(" AND (value ILIKE $%d OR source ILIKE $%d)", n, n)
		args = append(args, "%"+search+"%")
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
	err := s.rdb().SelectContext(ctx, &iocs, q, args...)
	return iocs, err
}

func (s *Store) GetIOC(ctx context.Context, id string) (*models.IOC, error) {
	var ioc models.IOC
	err := s.rdb().GetContext(ctx, &ioc, `SELECT * FROM iocs WHERE id=$1`, id)
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
	err := s.rdb().GetContext(ctx, &ioc, `
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
	err := s.rdb().SelectContext(ctx, &iocs, `
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

// ─── CVE Cache ───────────────────────────────────────────────────────────────

// GetCVE returns a cached CVE detail by ID.
func (s *Store) GetCVE(ctx context.Context, cveID string) (*models.CVEDetail, error) {
	var c models.CVEDetail
	err := s.rdb().GetContext(ctx, &c, `SELECT cve_id, severity, description, published_date, "references", exploit_available, cisa_kev, source, fetched_at FROM cve_cache WHERE cve_id=$1`, cveID)
	return &c, err
}

// UpsertCVE inserts or updates a CVE in the cache.
func (s *Store) UpsertCVE(ctx context.Context, c *models.CVEDetail) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cve_cache (cve_id, severity, description, published_date, "references", exploit_available, cisa_kev, source, fetched_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			severity = EXCLUDED.severity,
			description = EXCLUDED.description,
			published_date = EXCLUDED.published_date,
			"references" = EXCLUDED."references",
			exploit_available = EXCLUDED.exploit_available,
			cisa_kev = EXCLUDED.cisa_kev,
			source = EXCLUDED.source,
			fetched_at = NOW()
	`, c.CVEID, c.Severity, c.Description, c.PublishedDate, pq.Array(c.References), c.ExploitAvailable, c.CisaKEV, c.Source)
	return err
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
	err := s.rdb().SelectContext(ctx, &stats, q, since)
	return stats, err
}

func (s *Store) IOCStats(ctx context.Context) (*models.IOCStats, error) {
	var stats models.IOCStats
	err := s.rdb().GetContext(ctx, &stats, `
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

// ─── Pending Commands ───────────────────────────────────────────────────────

// CreatePendingCommand queues a command for later execution when an agent connects.
func (s *Store) CreatePendingCommand(ctx context.Context, cmd *models.PendingCommand) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_commands (id, agent_id, action, args, created_by, status)
		VALUES ($1, $2, $3, $4, $5, 'pending')
	`, cmd.ID, cmd.AgentID, cmd.Action, cmd.Args, cmd.CreatedBy)
	return err
}

// ListPendingCommands returns all commands for an agent, optionally filtered by status.
func (s *Store) ListPendingCommands(ctx context.Context, agentID, status string) ([]models.PendingCommand, error) {
	var cmds []models.PendingCommand
	q := `SELECT * FROM pending_commands WHERE agent_id=$1`
	args := []interface{}{agentID}
	if status != "" {
		q += ` AND status=$2`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC`
	err := s.rdb().SelectContext(ctx, &cmds, q, args...)
	if cmds == nil {
		cmds = []models.PendingCommand{}
	}
	return cmds, err
}

// ClaimPendingCommands atomically marks all pending commands for an agent as 'executing' and returns them.
func (s *Store) ClaimPendingCommands(ctx context.Context, agentID string) ([]models.PendingCommand, error) {
	var cmds []models.PendingCommand
	err := s.rdb().SelectContext(ctx, &cmds, `
		UPDATE pending_commands SET status='executing'
		WHERE agent_id=$1 AND status='pending'
		RETURNING *
	`, agentID)
	if cmds == nil {
		cmds = []models.PendingCommand{}
	}
	return cmds, err
}

// CompletePendingCommand marks a pending command as executed or failed.
func (s *Store) CompletePendingCommand(ctx context.Context, id, status string, result json.RawMessage) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE pending_commands SET status=$2, result=$3, executed_at=NOW()
		WHERE id=$1
	`, id, status, result)
	return err
}

// CancelPendingCommand marks a pending command as cancelled.
func (s *Store) CancelPendingCommand(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE pending_commands SET status='cancelled' WHERE id=$1 AND status='pending'
	`, id)
	return err
}

// ─── Database Size ──────────────────────────────────────────────────────────

// DBSizeTotal returns the total database size in bytes.
func (s *Store) DBSizeTotal(ctx context.Context) (int64, error) {
	var size int64
	err := s.db.QueryRowContext(ctx,
		`SELECT pg_database_size(current_database())`).Scan(&size)
	return size, err
}

// DBTableSizes returns the size of each major table in bytes.
func (s *Store) DBTableSizes(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT relname, pg_total_relation_size(c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		ORDER BY pg_total_relation_size(c.oid) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			return nil, err
		}
		result[name] = size
	}
	return result, rows.Err()
}

// AgentDBSize holds the event data size for one agent.
type AgentDBSize struct {
	AgentID  string `db:"agent_id" json:"agent_id"`
	Hostname string `db:"hostname" json:"hostname"`
	Bytes    int64  `db:"-"        json:"bytes"`
	Events   int64  `db:"events"   json:"events"`
}

// DBSizeByAgent returns the events table size approximation per agent.
func (s *Store) DBSizeByAgent(ctx context.Context) ([]AgentDBSize, error) {
	// Estimate per-agent size: count events and multiply by avg row size.
	var avgRowSize int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(
			pg_total_relation_size('events') / NULLIF((SELECT COUNT(*) FROM events), 0),
			0
		)
	`).Scan(&avgRowSize)
	if err != nil {
		return nil, err
	}

	var results []AgentDBSize
	err = s.rdb().SelectContext(ctx, &results, `
		SELECT e.agent_id, COALESCE(a.hostname, e.agent_id) AS hostname, COUNT(*) AS events
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		GROUP BY e.agent_id, a.hostname
		ORDER BY COUNT(*) DESC
	`)
	if err != nil {
		return nil, err
	}
	for i := range results {
		results[i].Bytes = results[i].Events * avgRowSize
	}
	return results, nil
}
