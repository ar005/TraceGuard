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

	"github.com/google/uuid"
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
	TenantID   string // restrict results to this tenant (empty = no filter for internal callers)
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
		if _, pidErr := strconv.Atoi(p.PID); pidErr != nil {
			return nil, fmt.Errorf("invalid pid: must be a number")
		}
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
	if p.TenantID != "" {
		query += fmt.Sprintf(` AND (tenant_id = $%d OR tenant_id = 'default' OR $%d = 'default')`, argN, argN)
		args = append(args, p.TenantID)
		argN++
	}

	query += fmt.Sprintf(` ORDER BY timestamp DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, p.Limit, p.Offset)

	var events []models.Event
	err := s.rdb().SelectContext(ctx, &events, query, args...)
	return events, err
}

func (s *Store) GetEvent(ctx context.Context, id, tenantID string) (*models.Event, error) {
	var e models.Event
	err := s.rdb().GetContext(ctx, &e,
		`SELECT * FROM events WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		id, tenantID)
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
	var srcIP interface{}
	if a.SrcIP != "" {
		srcIP = a.SrcIP
	}
	sourceTypes := a.SourceTypes
	if sourceTypes == nil {
		sourceTypes = pq.StringArray{}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts
		  (id, title, description, severity, status, rule_id, rule_name, mitre_ids, event_ids, agent_id, hostname, user_uid, source_types, src_ip, risk_score, first_seen, last_seen, hit_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW(),1)
		ON CONFLICT (id) DO UPDATE SET
			last_seen    = NOW(),
			hit_count    = alerts.hit_count + 1,
			event_ids    = alerts.event_ids || EXCLUDED.event_ids,
			source_types = (SELECT array_agg(DISTINCT x) FROM unnest(alerts.source_types || EXCLUDED.source_types) x),
			src_ip       = COALESCE(EXCLUDED.src_ip, alerts.src_ip),
			risk_score   = GREATEST(alerts.risk_score, EXCLUDED.risk_score),
			status       = CASE WHEN alerts.status='CLOSED' THEN 'OPEN' ELSE alerts.status END
	`, a.ID, a.Title, a.Description, a.Severity, a.Status,
		a.RuleID, a.RuleName, pq.Array(a.MitreIDs), pq.Array(a.EventIDs),
		a.AgentID, a.Hostname, a.UserUID, pq.Array(sourceTypes), srcIP, a.RiskScore)
	return err
}

// QueryAlertsParams defines filter/pagination for alert queries.
type QueryAlertsParams struct {
	AgentID  string
	Status   string
	Severity int16
	RuleID   string
	Search   string
	TenantID string
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
	if p.TenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argN)
		args = append(args, p.TenantID)
		argN++
	}

	query += fmt.Sprintf(` ORDER BY first_seen DESC LIMIT $%d OFFSET $%d`, argN, argN+1)
	args = append(args, p.Limit, p.Offset)

	var alerts []models.Alert
	err := s.rdb().SelectContext(ctx, &alerts, query, args...)
	return alerts, err
}

// UpdateAlertEnrichments merges threat intel results into alerts.enrichments.
func (s *Store) UpdateAlertEnrichments(ctx context.Context, alertID string, tenantID string, enrichments json.RawMessage) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET enrichments = $1 WHERE id = $2 AND tenant_id = $3`,
		enrichments, alertID, tenantID)
	return err
}

func (s *Store) GetAlert(ctx context.Context, id string, tenantID string) (*models.Alert, error) {
	var a models.Alert
	err := s.rdb().GetContext(ctx, &a,
		`SELECT * FROM alerts WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		id, tenantID)
	return &a, err
}

// GetAlertEvents returns all events associated with an alert.
// It queries by both alert_id column and the alert's event_ids array,
// deduplicating by event ID.
func (s *Store) GetAlertEvents(ctx context.Context, alertID, tenantID string) ([]models.Event, error) {
	alert, err := s.GetAlert(ctx, alertID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get alert: %w", err)
	}

	eventIDs := []string(alert.EventIDs)
	if len(eventIDs) == 0 {
		var events []models.Event
		err = s.rdb().SelectContext(ctx, &events,
			`SELECT * FROM events WHERE alert_id=$1 ORDER BY timestamp DESC LIMIT 500`,
			alertID)
		return events, err
	}

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

func (s *Store) UpdateAlertStatus(ctx context.Context, id, tenantID, status, assignee, notes string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET status=$3, assignee=$4, notes=$5
		 WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		id, tenantID, status, assignee, notes)
	return err
}

func (s *Store) UpdateAlertTriage(ctx context.Context, id, tenantID, verdict string, score int16, notes string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET triage_verdict=$3, triage_score=$4, triage_notes=$5, triage_at=NOW()
		 WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		id, tenantID, verdict, score, notes)
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

func (s *Store) ListRules(ctx context.Context, tenantID string) ([]models.Rule, error) {
	var rules []models.Rule
	err := s.rdb().SelectContext(ctx, &rules,
		`SELECT * FROM rules WHERE (tenant_id=$1 OR tenant_id='default' OR $1='default') ORDER BY severity DESC, name`,
		tenantID)
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
		SELECT id, tenant_id, title, description, severity, status, rule_id, rule_name,
		       mitre_ids, event_ids, agent_id, hostname, user_uid, source_types,
		       COALESCE(src_ip::text, '') AS src_ip,
		       first_seen, last_seen, hit_count
		FROM alerts
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
func (s *Store) HuntQuery(ctx context.Context, tenantID string, query string, limit int) ([]models.Event, int, error) {
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

	// Always inject tenant isolation — user-supplied WHERE clause sits inside it.
	tenantParam := len(args) + 1
	limitParam := tenantParam + 1
	dataSQL := fmt.Sprintf(
		`SELECT * FROM events WHERE tenant_id = $%d AND (%s) ORDER BY timestamp DESC LIMIT $%d`,
		tenantParam, whereClause, limitParam)
	countSQL := fmt.Sprintf(
		`SELECT COUNT(*) FROM events WHERE tenant_id = $%d AND (%s)`,
		tenantParam, whereClause)
	args = append(args, tenantID)

	allArgs := append(args, limit)

	// Cap query execution time to prevent long-running table scans.
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	type dataResult struct {
		events []models.Event
		err    error
	}
	type countResult struct {
		total int
		err   error
	}
	dataCh := make(chan dataResult, 1)
	countCh := make(chan countResult, 1)

	go func() {
		var evs []models.Event
		err := s.rdb().SelectContext(qCtx, &evs, dataSQL, allArgs...)
		dataCh <- dataResult{evs, err}
	}()
	go func() {
		var n int
		err := s.rdb().QueryRowContext(qCtx, countSQL, args...).Scan(&n)
		countCh <- countResult{n, err}
	}()

	dr := <-dataCh
	cr := <-countCh
	if dr.err != nil {
		return nil, 0, fmt.Errorf("hunt query failed: %w", dr.err)
	}
	if cr.err != nil {
		return nil, 0, fmt.Errorf("hunt count failed: %w", cr.err)
	}

	return dr.events, cr.total, nil
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
// indexOperator finds op in s only at a word boundary (surrounded by spaces or string edges).
// This prevents substring matches like "exeLike" being mistaken for "LIKE" operator.
func indexOperator(s, op string) int {
	idx := 0
	for {
		i := strings.Index(s[idx:], op)
		if i < 0 {
			return -1
		}
		abs := idx + i
		before := abs == 0 || s[abs-1] == ' '
		after := abs+len(op) >= len(s) || s[abs+len(op)] == ' ' || s[abs+len(op)] == '\''
		if before && after {
			return abs
		}
		idx = abs + 1
		if idx >= len(s) {
			return -1
		}
	}
}

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
			// Word operators: use indexOperator for strict word-boundary matching.
			idx = indexOperator(upperPart, opUpper)
			if idx >= 0 {
				col := strings.TrimSpace(part[:idx])
				val := strings.TrimSpace(part[idx+len(op):])
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
	if inc.TenantID == "" {
		inc.TenantID = "default"
	}
	if inc.AlertIDs == nil { inc.AlertIDs = pq.StringArray{} }
	if inc.AgentIDs == nil { inc.AgentIDs = pq.StringArray{} }
	if inc.Hostnames == nil { inc.Hostnames = pq.StringArray{} }
	if inc.MitreIDs == nil { inc.MitreIDs = pq.StringArray{} }
	if inc.UserUIDs == nil { inc.UserUIDs = pq.StringArray{} }
	if inc.SrcIPs == nil { inc.SrcIPs = pq.StringArray{} }
	if inc.SourceTypes == nil { inc.SourceTypes = pq.StringArray{} }
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents
		  (id, tenant_id, title, description, severity, status, alert_ids, agent_ids, hostnames, mitre_ids,
		   user_uids, src_ips, source_types, alert_count, first_seen, last_seen, assignee, notes, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW(),NOW())`,
		inc.ID, inc.TenantID, inc.Title, inc.Description, inc.Severity, inc.Status,
		pq.Array(inc.AlertIDs), pq.Array(inc.AgentIDs), pq.Array(inc.Hostnames), pq.Array(inc.MitreIDs),
		pq.Array(inc.UserUIDs), pq.Array(inc.SrcIPs), pq.Array(inc.SourceTypes),
		inc.AlertCount, inc.FirstSeen, inc.LastSeen, inc.Assignee, inc.Notes)
	return err
}

// QueryIncidentsParams defines filter/pagination for incident queries.
type QueryIncidentsParams struct {
	TenantID string
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
	if p.TenantID == "" {
		p.TenantID = "default"
	}
	query := `SELECT * FROM incidents WHERE (tenant_id=$1 OR tenant_id='default' OR $1='default')`
	args := []interface{}{p.TenantID}
	n := 1
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
func (s *Store) GetIncident(ctx context.Context, id, tenantID string) (*models.Incident, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	var inc models.Incident
	err := s.rdb().GetContext(ctx, &inc,
		`SELECT * FROM incidents WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		id, tenantID)
	return &inc, err
}

// UpdateIncident updates mutable incident fields.
func (s *Store) UpdateIncident(ctx context.Context, id, tenantID, status, assignee, notes string) error {
	if tenantID == "" {
		tenantID = "default"
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET status=$3, assignee=$4, notes=$5, updated_at=NOW()
		WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		id, tenantID, status, assignee, notes)
	return err
}

// FindOpenIncident finds an existing OPEN/INVESTIGATING incident for the given
// agent_id that was last seen within the correlation window.
func (s *Store) FindOpenIncident(ctx context.Context, agentID, tenantID string, window time.Duration) (*models.Incident, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	var inc models.Incident
	cutoff := time.Now().Add(-window)
	err := s.rdb().GetContext(ctx, &inc, `
		SELECT * FROM incidents
		WHERE $1 = ANY(agent_ids)
		  AND (tenant_id=$3 OR tenant_id='default' OR $3='default')
		  AND status IN ('OPEN','INVESTIGATING')
		  AND last_seen >= $2
		ORDER BY last_seen DESC LIMIT 1`, agentID, cutoff, tenantID)
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
func (s *Store) FindOpenIncidentXdr(ctx context.Context, agentID, userUID, srcIP, tenantID string, window time.Duration) (*models.Incident, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	var inc models.Incident
	cutoff := time.Now().Add(-window)
	err := s.rdb().GetContext(ctx, &inc, `
		SELECT * FROM incidents
		WHERE status IN ('OPEN','INVESTIGATING')
		  AND (tenant_id=$5 OR tenant_id='default' OR $5='default')
		  AND last_seen >= $4
		  AND (
		      ($1 != '' AND $1 = ANY(agent_ids))
		   OR ($2 != '' AND $2 = ANY(user_uids))
		   OR ($3 != '' AND $3::inet = ANY(src_ips))
		  )
		ORDER BY last_seen DESC LIMIT 1`, agentID, userUID, srcIP, cutoff, tenantID)
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

// GetIncidentTimeline returns a chronological list of events correlated with
// the incident: any event from an involved agent, user identity, or source IP
// within ±5 minutes of the incident window. Capped at 500 rows.
func (s *Store) GetIncidentTimeline(ctx context.Context, incidentID, tenantID string) ([]models.Event, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	inc, err := s.GetIncident(ctx, incidentID, tenantID)
	if err != nil {
		return nil, err
	}
	if len(inc.AgentIDs) == 0 && len(inc.UserUIDs) == 0 {
		return []models.Event{}, nil
	}

	start := inc.FirstSeen.Add(-5 * time.Minute)
	end := inc.LastSeen.Add(5 * time.Minute)

	var events []models.Event
	err = s.rdb().SelectContext(ctx, &events, `
		SELECT id, agent_id, hostname, event_type, timestamp, payload, received_at,
		       severity, rule_id, alert_id,
		       COALESCE(source_type,'') AS source_type,
		       COALESCE(user_uid,'')    AS user_uid,
		       COALESCE(tenant_id,'')   AS tenant_id
		FROM events
		WHERE (tenant_id = $1 OR tenant_id = 'default' OR $1 = 'default')
		  AND timestamp BETWEEN $2 AND $3
		  AND (
		        agent_id = ANY($4)
		     OR (user_uid != '' AND user_uid = ANY($5))
		  )
		ORDER BY timestamp ASC
		LIMIT 500
	`, tenantID, start, end, pq.Array([]string(inc.AgentIDs)), pq.Array([]string(inc.UserUIDs)))
	return events, err
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


// ─── YARA Rules ───────────────────────────────────────────────────────────────

func (s *Store) ListYARARules(ctx context.Context) ([]models.YARARule, error) {
	var rules []models.YARARule
	err := s.rdb().SelectContext(ctx, &rules,
		`SELECT * FROM yara_rules ORDER BY created_at DESC`)
	return rules, err
}

func (s *Store) ListEnabledYARARules(ctx context.Context) ([]models.YARARule, error) {
	var rules []models.YARARule
	err := s.rdb().SelectContext(ctx, &rules,
		`SELECT * FROM yara_rules WHERE enabled=TRUE ORDER BY created_at DESC`)
	return rules, err
}

func (s *Store) GetYARARule(ctx context.Context, id string) (*models.YARARule, error) {
	var r models.YARARule
	err := s.rdb().GetContext(ctx, &r, `SELECT * FROM yara_rules WHERE id=$1`, id)
	return &r, err
}

func (s *Store) UpsertYARARule(ctx context.Context, r *models.YARARule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO yara_rules (id, name, description, rule_text, enabled, severity, mitre_ids, tags, author, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			name        = EXCLUDED.name,
			description = EXCLUDED.description,
			rule_text   = EXCLUDED.rule_text,
			enabled     = EXCLUDED.enabled,
			severity    = EXCLUDED.severity,
			mitre_ids   = EXCLUDED.mitre_ids,
			tags        = EXCLUDED.tags,
			author      = EXCLUDED.author,
			updated_at  = NOW()`,
		r.ID, r.Name, r.Description, r.RuleText, r.Enabled, r.Severity,
		pq.Array(r.MitreIDs), pq.Array(r.Tags), r.Author)
	return err
}

func (s *Store) DeleteYARARule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM yara_rules WHERE id=$1`, id)
	return err
}

// ─── Incident Attack Graph ─────────────────────────────────────────────────────

// GraphNode is a vertex in the incident attack story.
type GraphNode struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`   // "host", "user", "alert", "ip", "process", "file"
	Label    string            `json:"label"`
	Severity int16             `json:"severity,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// GraphEdge is a directed relationship between two graph nodes.
type GraphEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

// IncidentGraph is the attack story returned for an incident.
type IncidentGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GetIncidentGraph builds an attack story graph for an incident from its alerts and events.
func (s *Store) GetIncidentGraph(ctx context.Context, incidentID, tenantID string) (*IncidentGraph, error) {
	if tenantID == "" {
		tenantID = "default"
	}

	// Load the incident.
	var inc models.Incident
	err := s.rdb().GetContext(ctx, &inc,
		`SELECT * FROM incidents WHERE id=$1 AND (tenant_id=$2 OR tenant_id='default' OR $2='default')`,
		incidentID, tenantID)
	if err != nil {
		return nil, err
	}

	// Load all linked alerts.
	var alerts []models.Alert
	if err := s.rdb().SelectContext(ctx, &alerts,
		`SELECT * FROM alerts WHERE incident_id=$1 ORDER BY first_seen ASC`, incidentID); err != nil {
		return nil, err
	}

	nodes := make([]GraphNode, 0, 16)
	edges := make([]GraphEdge, 0, 32)
	seen := make(map[string]bool)

	addNode := func(n GraphNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			nodes = append(nodes, n)
		}
	}
	edgeID := 0
	addEdge := func(src, tgt, label string) {
		edgeID++
		edges = append(edges, GraphEdge{
			ID:     fmt.Sprintf("e%d", edgeID),
			Source: src,
			Target: tgt,
			Label:  label,
		})
	}

	// Host nodes from incident.
	for _, h := range inc.Hostnames {
		hid := "host:" + h
		addNode(GraphNode{ID: hid, Type: "host", Label: h})
	}
	// User nodes.
	for _, u := range inc.UserUIDs {
		if u == "" {
			continue
		}
		uid := "user:" + u
		addNode(GraphNode{ID: uid, Type: "user", Label: u})
	}
	// Source IP nodes.
	for _, ip := range inc.SrcIPs {
		if ip == "" {
			continue
		}
		ipid := "ip:" + ip
		addNode(GraphNode{ID: ipid, Type: "ip", Label: ip})
	}

	// Alert nodes + their edges to hosts/users.
	for i := range alerts {
		a := &alerts[i]
		aid := "alert:" + a.ID
		meta := map[string]string{
			"rule":   a.RuleName,
			"status": a.Status,
		}
		if len(a.MitreIDs) > 0 {
			meta["mitre"] = a.MitreIDs[0]
		}
		addNode(GraphNode{ID: aid, Type: "alert", Label: a.Title, Severity: a.Severity, Meta: meta})

		// Edge: host → alert
		hid := "host:" + a.Hostname
		addNode(GraphNode{ID: hid, Type: "host", Label: a.Hostname})
		addEdge(hid, aid, "triggered")

		// Edge: user → alert (if present)
		if a.UserUID != "" {
			uid := "user:" + a.UserUID
			addNode(GraphNode{ID: uid, Type: "user", Label: a.UserUID})
			addEdge(uid, aid, "actor")
		}
	}

	// Load raw events for the first 200 events across all alerts to find process/IP nodes.
	alertIDs := make([]string, 0, len(alerts))
	for _, a := range alerts {
		alertIDs = append(alertIDs, a.EventIDs...)
	}
	if len(alertIDs) > 200 {
		alertIDs = alertIDs[:200]
	}
	if len(alertIDs) > 0 {
		query, args, qErr := sqlx.In(
			`SELECT id, event_type, agent_id, payload FROM events WHERE id IN (?) LIMIT 200`, alertIDs)
		if qErr == nil {
			query = s.rdb().Rebind(query)
			rows, rErr := s.rdb().QueryxContext(ctx, query, args...)
			if rErr == nil {
				defer rows.Close()
				for rows.Next() {
					var evID, evType, agentID string
					var payload []byte
					if err := rows.Scan(&evID, &evType, &agentID, &payload); err != nil {
						continue
					}
					var p map[string]interface{}
					if err := json.Unmarshal(payload, &p); err != nil {
						continue
					}
					// Derive process node from process events.
					if evType == "PROCESS_EXEC" {
						comm, _ := p["process.comm"].(string)
						pid, _ := p["process.pid"].(float64)
						if comm != "" {
							nid := fmt.Sprintf("proc:%s:%.0f", agentID, pid)
							addNode(GraphNode{ID: nid, Type: "process", Label: comm,
								Meta: map[string]string{"agent": agentID}})
							hid := "host:" + agentID
							addEdge(hid, nid, "ran")
						}
					}
					// Derive IP node from network events.
					if evType == "NET_CONNECT" {
						dst, _ := p["dst_ip"].(string)
						dport, _ := p["dst_port"].(float64)
						if dst != "" {
							ipid := "ip:" + dst
							addNode(GraphNode{ID: ipid, Type: "ip", Label: dst,
								Meta: map[string]string{"port": fmt.Sprintf("%.0f", dport)}})
							hid := "host:" + agentID
							addEdge(hid, ipid, fmt.Sprintf("connected:%.0f", dport))
						}
					}
				}
			}
		}
	}

	return &IncidentGraph{Nodes: nodes, Edges: edges}, nil
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

// ── Host risk ─────────────────────────────────────────────────────────────────

func (s *Store) UpdateAgentRisk(ctx context.Context, agentID string, score int16, factors []string) error {
	raw, err := json.Marshal(factors)
	if err != nil {
		raw = []byte(`[]`)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE agents SET risk_score=$1, risk_factors=$2, risk_updated_at=NOW() WHERE id=$3`,
		score, raw, agentID)
	return err
}

func (s *Store) GetAgentRisk(ctx context.Context, agentID string) (score int16, factors json.RawMessage, err error) {
	err = s.rdb().QueryRowContext(ctx,
		`SELECT risk_score, risk_factors FROM agents WHERE id=$1`, agentID).
		Scan(&score, &factors)
	return
}

func (s *Store) ListTopRiskAgents(ctx context.Context, limit int) ([]models.Agent, error) {
	var agents []models.Agent
	err := s.rdb().SelectContext(ctx, &agents, `
		SELECT id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen,
		       is_online, config_ver, tags, env, notes, winevent_config,
		       risk_score, risk_factors, risk_updated_at
		FROM agents WHERE risk_score > 0
		ORDER BY risk_score DESC LIMIT $1`, limit)
	return agents, err
}

// ── Login sessions ─────────────────────────────────────────────────────────────

func (s *Store) InsertLoginSession(ctx context.Context, ls *models.LoginSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO login_sessions (id, tenant_id, user_uid, agent_id, src_ip, hostname, logged_in_at, event_id)
		VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING`,
		ls.ID, ls.TenantID, ls.UserUID, ls.AgentID, ls.SrcIP, ls.Hostname, ls.LoggedInAt, ls.EventID)
	return err
}

func (s *Store) CloseLoginSession(ctx context.Context, userUID, tenantID string, loggedOutAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE login_sessions
		SET logged_out_at=$1,
		    duration_s=EXTRACT(EPOCH FROM ($1 - logged_in_at))::INTEGER
		WHERE id = (
		    SELECT id FROM login_sessions
		    WHERE user_uid=$2 AND tenant_id=$3 AND logged_out_at IS NULL
		    ORDER BY logged_in_at DESC
		    LIMIT 1
		)`,
		loggedOutAt, userUID, tenantID)
	return err
}

func (s *Store) ListLoginSessions(ctx context.Context, tenantID, userUID string, limit int) ([]models.LoginSession, error) {
	rows, err := s.rdb().QueryxContext(ctx, `
		SELECT id, tenant_id, user_uid, agent_id,
		       COALESCE(src_ip::text,'') AS src_ip,
		       hostname, logged_in_at, logged_out_at, duration_s, event_id, created_at
		FROM login_sessions
		WHERE tenant_id=$1 AND ($2='' OR user_uid=$2)
		ORDER BY logged_in_at DESC LIMIT $3`,
		tenantID, userUID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.LoginSession
	for rows.Next() {
		var ls models.LoginSession
		var srcIP string
		if err := rows.Scan(&ls.ID, &ls.TenantID, &ls.UserUID, &ls.AgentID,
			&srcIP, &ls.Hostname, &ls.LoggedInAt, &ls.LoggedOutAt,
			&ls.DurationS, &ls.EventID, &ls.CreatedAt); err != nil {
			return nil, err
		}
		if srcIP != "" {
			ipCopy := srcIP
			ls.SrcIP = &ipCopy
		}
		out = append(out, ls)
	}
	return out, rows.Err()
}

// ── Auto-case policies ────────────────────────────────────────────────────────

func (s *Store) ListAutoCasePolicies(ctx context.Context, tenantID string) ([]models.AutoCasePolicy, error) {
	var out []models.AutoCasePolicy
	err := s.rdb().SelectContext(ctx, &out,
		`SELECT * FROM auto_case_policies WHERE tenant_id=$1 AND enabled=TRUE ORDER BY min_severity DESC`,
		tenantID)
	return out, err
}

func (s *Store) UpsertAutoCasePolicy(ctx context.Context, p *models.AutoCasePolicy) error {
	ruleIDs := p.RuleIDs
	if ruleIDs == nil {
		ruleIDs = pq.StringArray{}
	}
	mitreIDs := p.MitreIDs
	if mitreIDs == nil {
		mitreIDs = pq.StringArray{}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auto_case_policies (id, tenant_id, name, min_severity, rule_ids, mitre_ids, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
		    name=$3, min_severity=$4, rule_ids=$5, mitre_ids=$6, enabled=$7, updated_at=NOW()`,
		p.ID, p.TenantID, p.Name, p.MinSeverity,
		pq.Array(ruleIDs), pq.Array(mitreIDs), p.Enabled)
	return err
}

// ── Beaconing ─────────────────────────────────────────────────────────────────

func (s *Store) MarkBeaconingAlertFired(ctx context.Context, agentID, dstIP string, dstPort int) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE beaconing_state SET alert_fired=TRUE
		WHERE agent_id=$1 AND dst_ip=$2::inet AND dst_port=$3`,
		agentID, dstIP, dstPort)
	return err
}

// ── Lateral movement ──────────────────────────────────────────────────────────

// LateralMovementHit is a DB result row for lateral movement sweep.
type LateralMovementHit struct {
	UserUID    string `db:"user_uid"`
	TenantID   string `db:"tenant_id"`
	AgentCount int    `db:"agent_count"`
}

// LateralMovementQuery finds users with sessions on >lateralThresh agents within window.
func (s *Store) LateralMovementQuery(ctx context.Context, tenantID string, window time.Duration) ([]models.LateralHit, error) {
	seconds := int(window.Seconds())
	rows, err := s.rdb().QueryxContext(ctx, `
		SELECT user_uid, tenant_id, COUNT(DISTINCT agent_id) AS agent_count
		FROM login_sessions
		WHERE ($1='' OR tenant_id=$1)
		  AND logged_in_at > NOW() - ($2 || ' seconds')::INTERVAL
		  AND agent_id != ''
		GROUP BY user_uid, tenant_id
		HAVING COUNT(DISTINCT agent_id) > 2`,
		tenantID, seconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hits []models.LateralHit
	for rows.Next() {
		var row LateralMovementHit
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		// Fetch agent IDs and hostnames for this user
		var agentIDs []string
		var hostnames []string
		agentRows, err := s.rdb().QueryxContext(ctx, `
			SELECT DISTINCT ls.agent_id, COALESCE(a.hostname, ls.agent_id) AS hostname
			FROM login_sessions ls
			LEFT JOIN agents a ON a.id = ls.agent_id
			WHERE ls.user_uid=$1 AND ($2='' OR ls.tenant_id=$2)
			  AND ls.logged_in_at > NOW() - ($3 || ' seconds')::INTERVAL
			  AND ls.agent_id != ''
			LIMIT 10`, row.UserUID, tenantID, seconds)
		if err == nil {
			for agentRows.Next() {
				var aid, hostname string
				if err := agentRows.Scan(&aid, &hostname); err == nil {
					agentIDs = append(agentIDs, aid)
					hostnames = append(hostnames, hostname)
				}
			}
			agentRows.Close()
		}
		hits = append(hits, models.LateralHit{
			UserUID:    row.UserUID,
			TenantID:   row.TenantID,
			AgentCount: row.AgentCount,
			AgentIDs:   agentIDs,
			Hostnames:  hostnames,
		})
	}
	return hits, rows.Err()
}

// ── Reports ───────────────────────────────────────────────────────────────────

// Report is a generated export record.
type Report struct {
	ID          string     `db:"id"           json:"id"`
	TenantID    string     `db:"tenant_id"    json:"tenant_id"`
	Title       string     `db:"title"        json:"title"`
	Type        string     `db:"type"         json:"type"`
	Format      string     `db:"format"       json:"format"`
	Status      string     `db:"status"       json:"status"`
	RowCount    int        `db:"row_count"    json:"row_count"`
	Data        string     `db:"data"         json:"data,omitempty"`
	CreatedBy   string     `db:"created_by"   json:"created_by"`
	CreatedAt   time.Time  `db:"created_at"   json:"created_at"`
	CompletedAt *time.Time `db:"completed_at" json:"completed_at,omitempty"`
}

func (s *Store) InsertReport(ctx context.Context, r *Report) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO reports (id, tenant_id, title, type, format, status, row_count, data, created_by, created_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		r.ID, r.TenantID, r.Title, r.Type, r.Format, r.Status, r.RowCount,
		r.Data, r.CreatedBy, now, r.CompletedAt)
	return err
}

func (s *Store) ListReports(ctx context.Context, tenantID string) ([]Report, error) {
	var out []Report
	err := s.rdb().SelectContext(ctx, &out,
		`SELECT id, tenant_id, title, type, format, status, row_count, created_by, created_at, completed_at
		 FROM reports WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tenantID)
	return out, err
}

func (s *Store) GetReport(ctx context.Context, id, tenantID string) (*Report, error) {
	var r Report
	err := s.rdb().GetContext(ctx, &r,
		`SELECT * FROM reports WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GenerateAlertsCSV returns a CSV of recent alerts for a tenant.
func (s *Store) GenerateAlertsCSV(ctx context.Context, tenantID string, limit int) (string, int, error) {
	rows, err := s.rdb().QueryxContext(ctx, `
		SELECT id, title, severity, status, rule_name, hostname, src_ip, first_seen, last_seen
		FROM alerts WHERE tenant_id=$1 ORDER BY first_seen DESC LIMIT $2`,
		tenantID, limit)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	var sb strings.Builder
	sb.WriteString("id,title,severity,status,rule_name,hostname,src_ip,first_seen,last_seen\n")
	count := 0
	for rows.Next() {
		var id, title, status, ruleName, hostname string
		var srcIP *string
		var severity int16
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&id, &title, &severity, &status, &ruleName, &hostname, &srcIP, &firstSeen, &lastSeen); err != nil {
			return "", 0, err
		}
		ip := ""
		if srcIP != nil {
			ip = *srcIP
		}
		sb.WriteString(fmt.Sprintf("%s,%s,%d,%s,%s,%s,%s,%s,%s\n",
			csvEscape(id), csvEscape(title), severity, csvEscape(status),
			csvEscape(ruleName), csvEscape(hostname), csvEscape(ip),
			firstSeen.Format(time.RFC3339), lastSeen.Format(time.RFC3339)))
		count++
	}
	return sb.String(), count, rows.Err()
}

// GenerateIncidentsCSV returns a CSV of recent incidents for a tenant.
func (s *Store) GenerateIncidentsCSV(ctx context.Context, tenantID string, limit int) (string, int, error) {
	rows, err := s.rdb().QueryxContext(ctx, `
		SELECT id, title, severity, status, alert_count, first_seen, last_seen
		FROM incidents WHERE tenant_id=$1 ORDER BY first_seen DESC LIMIT $2`,
		tenantID, limit)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	var sb strings.Builder
	sb.WriteString("id,title,severity,status,alert_count,first_seen,last_seen\n")
	count := 0
	for rows.Next() {
		var id, title, status string
		var severity int16
		var alertCount int
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&id, &title, &severity, &status, &alertCount, &firstSeen, &lastSeen); err != nil {
			return "", 0, err
		}
		sb.WriteString(fmt.Sprintf("%s,%s,%d,%s,%d,%s,%s\n",
			csvEscape(id), csvEscape(title), severity, csvEscape(status),
			alertCount, firstSeen.Format(time.RFC3339), lastSeen.Format(time.RFC3339)))
		count++
	}
	return sb.String(), count, rows.Err()
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// ── Feature B: Auto-Remediation Rules ─────────────────────────────────────

func (s *Store) ListAutoRemediationRules(ctx context.Context, tenantID string) ([]models.AutoRemediationRule, error) {
	var rules []models.AutoRemediationRule
	err := s.db.SelectContext(ctx, &rules,
		`SELECT id, tenant_id, name, trigger_type, trigger_value, action, playbook_id, min_severity, enabled, created_at
         FROM auto_remediation_rules WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (s *Store) UpsertAutoRemediationRule(ctx context.Context, r *models.AutoRemediationRule) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auto_remediation_rules(id,tenant_id,name,trigger_type,trigger_value,action,playbook_id,min_severity,enabled,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
         ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name, trigger_type=EXCLUDED.trigger_type,
           trigger_value=EXCLUDED.trigger_value, action=EXCLUDED.action, playbook_id=EXCLUDED.playbook_id,
           min_severity=EXCLUDED.min_severity, enabled=EXCLUDED.enabled`,
		r.ID, r.TenantID, r.Name, r.TriggerType, r.TriggerValue, r.Action, r.PlaybookID, r.MinSeverity, r.Enabled)
	return err
}

func (s *Store) DeleteAutoRemediationRule(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM auto_remediation_rules WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// ── Feature C: UEBA Timeline ──────────────────────────────────────────────

// UEBAEvent is a timeline entry for a user's activity across all sources.
type UEBAEvent struct {
	Time     time.Time `json:"time"`
	Category string    `json:"category"` // login | process | network | file | alert
	Summary  string    `json:"summary"`
	AgentID  string    `json:"agent_id"`
	Hostname string    `json:"hostname"`
	Severity int       `json:"severity,omitempty"`
	AlertID  string    `json:"alert_id,omitempty"`
}

func (s *Store) GetUEBATimeline(ctx context.Context, tenantID, userUID string, hours int) ([]UEBAEvent, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	var events []UEBAEvent

	// Login sessions
	rows, err := s.db.QueryContext(ctx,
		`SELECT logged_in_at, agent_id, COALESCE(src_ip::text,'') FROM login_sessions
         WHERE tenant_id=$1 AND user_uid=$2 AND logged_in_at >= $3 ORDER BY logged_in_at DESC LIMIT 200`,
		tenantID, userUID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t time.Time
		var agentID, srcIP string
		if err := rows.Scan(&t, &agentID, &srcIP); err != nil {
			continue
		}
		events = append(events, UEBAEvent{Time: t, Category: "login", Summary: "Login from " + srcIP, AgentID: agentID})
	}

	// Alerts involving this user
	alertRows, err := s.db.QueryContext(ctx,
		`SELECT first_seen, id, title, severity, agent_id FROM alerts
         WHERE tenant_id=$1 AND user_uid=$2 AND created_at >= $3 ORDER BY created_at DESC LIMIT 100`,
		tenantID, userUID, since)
	if err != nil {
		return nil, err
	}
	defer alertRows.Close()
	for alertRows.Next() {
		var t time.Time
		var id, title, agentID string
		var sev int
		if err := alertRows.Scan(&t, &id, &title, &sev, &agentID); err != nil {
			continue
		}
		events = append(events, UEBAEvent{Time: t, Category: "alert", Summary: title, AgentID: agentID, Severity: sev, AlertID: id})
	}

	// Sort by time descending
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].Time.After(events[i].Time) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}
	return events, nil
}

// ── Feature G: Custom IOC Feeds ───────────────────────────────────────────

func (s *Store) ListCustomIOCFeeds(ctx context.Context, tenantID string) ([]models.CustomIOCFeed, error) {
	var feeds []models.CustomIOCFeed
	err := s.db.SelectContext(ctx, &feeds,
		`SELECT id, tenant_id, name, url, format, feed_type, enabled, last_synced_at, entry_count, created_at
         FROM custom_ioc_feeds WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	return feeds, err
}

func (s *Store) UpsertCustomIOCFeed(ctx context.Context, f *models.CustomIOCFeed) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO custom_ioc_feeds(id,tenant_id,name,url,format,feed_type,enabled,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
         ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name, url=EXCLUDED.url,
           format=EXCLUDED.format, feed_type=EXCLUDED.feed_type, enabled=EXCLUDED.enabled`,
		f.ID, f.TenantID, f.Name, f.URL, f.Format, f.FeedType, f.Enabled)
	return err
}

func (s *Store) DeleteCustomIOCFeed(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM custom_ioc_feeds WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (s *Store) MarkCustomFeedSynced(ctx context.Context, id string, count int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE custom_ioc_feeds SET last_synced_at=NOW(), entry_count=$1 WHERE id=$2`, count, id)
	return err
}

// ── Feature H: Attack Graph ───────────────────────────────────────────────

// AttackGraphNode represents a single alert in the incident attack graph.
type AttackGraphNode struct {
	ID        string    `json:"id"`
	Tactic    string    `json:"tactic"`
	Technique string    `json:"technique"`
	EventType string    `json:"event_type"`
	Hostname  string    `json:"hostname"`
	AgentID   string    `json:"agent_id"`
	Time      time.Time `json:"time"`
	Summary   string    `json:"summary"`
}

// AttackGraphEdge is a directed link between two nodes in the attack graph.
type AttackGraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

// AttackGraph is the full graph for one incident.
type AttackGraph struct {
	IncidentID string            `json:"incident_id"`
	Nodes      []AttackGraphNode `json:"nodes"`
	Edges      []AttackGraphEdge `json:"edges"`
}

func (s *Store) GetIncidentAttackGraph(ctx context.Context, tenantID, incidentID string) (*AttackGraph, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.title, a.rule_id, a.mitre_ids, a.agent_id, a.first_seen,
                COALESCE(ag.hostname,'') as hostname
         FROM alerts a
         LEFT JOIN agents ag ON ag.id=a.agent_id
         WHERE a.tenant_id=$1 AND a.incident_id=$2
         ORDER BY a.first_seen ASC`,
		tenantID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	graph := &AttackGraph{IncidentID: incidentID}
	var prevID string
	for rows.Next() {
		var id, title, ruleID, agentID, hostname string
		var mitreIDs pq.StringArray
		var t time.Time
		if err := rows.Scan(&id, &title, &ruleID, &mitreIDs, &agentID, &t, &hostname); err != nil {
			continue
		}
		tactic := mitreToTactic(mitreIDs)
		technique := ""
		if len(mitreIDs) > 0 {
			technique = mitreIDs[0]
		}
		node := AttackGraphNode{
			ID: id, Tactic: tactic, Technique: technique,
			AgentID: agentID, Hostname: hostname, Time: t, Summary: title,
		}
		graph.Nodes = append(graph.Nodes, node)
		if prevID != "" {
			graph.Edges = append(graph.Edges, AttackGraphEdge{Source: prevID, Target: id, Label: "followed by"})
		}
		prevID = id
	}
	return graph, nil
}

// mitreToTactic maps the first MITRE ID prefix to a kill-chain tactic name.
func mitreToTactic(ids pq.StringArray) string {
	if len(ids) == 0 {
		return "Unknown"
	}
	id := ids[0]
	switch {
	case id == "T1059" || id == "T1204" || id == "T1106":
		return "Execution"
	case id == "T1003" || id == "T1078" || id == "T1110":
		return "Credential Access"
	case id == "T1021" || id == "T1550" || id == "T1076":
		return "Lateral Movement"
	case id == "T1048" || id == "T1041" || id == "T1071":
		return "Exfiltration"
	case id == "T1486" || id == "T1490":
		return "Impact"
	case id == "T1055" || id == "T1134":
		return "Privilege Escalation"
	case id == "T1053" || id == "T1543" || id == "T1547":
		return "Persistence"
	case id == "T1046" || id == "T1018":
		return "Discovery"
	case id == "T1036" || id == "T1027":
		return "Defense Evasion"
	default:
		return "Other"
	}
}

// ── DNS Intelligence ──────────────────────────────────────────────────────────

// DNSDomainStat holds a base domain and its query statistics.
type DNSDomainStat struct {
	Domain     string `db:"domain"      json:"domain"`
	Count      int    `db:"count"       json:"count"`
	AgentCount int    `db:"agent_count" json:"agent_count"`
}

// QueryDNSEvents returns DNS events for a tenant, optionally filtered by agent and domain.
func (s *Store) QueryDNSEvents(ctx context.Context, tenantID, agentID, domain string, limit, offset int) ([]models.Event, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	args := []interface{}{tenantID}
	where := "WHERE event_type IN ('DNS_QUERY','DNS_LOOKUP','NETWORK_DNS') AND tenant_id=$1"
	n := 2
	if agentID != "" {
		where += fmt.Sprintf(" AND agent_id=$%d", n)
		args = append(args, agentID)
		n++
	}
	if domain != "" {
		where += fmt.Sprintf(" AND payload::text ILIKE $%d", n)
		args = append(args, "%"+domain+"%")
		n++
	}

	var total int
	if err := s.rdb().QueryRowContext(ctx, "SELECT COUNT(*) FROM events "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.rdb().QueryxContext(ctx,
		"SELECT * FROM events "+where+" ORDER BY timestamp DESC LIMIT $"+fmt.Sprint(n)+" OFFSET $"+fmt.Sprint(n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var evs []models.Event
	for rows.Next() {
		var ev models.Event
		if err := rows.StructScan(&ev); err != nil {
			return nil, 0, err
		}
		evs = append(evs, ev)
	}
	return evs, total, rows.Err()
}

// DNSTopDomains returns the top queried base domains for a tenant in the last hoursBack hours.
func (s *Store) DNSTopDomains(ctx context.Context, tenantID string, hoursBack, limit int) ([]DNSDomainStat, error) {
	if hoursBack <= 0 {
		hoursBack = 24
	}
	if limit <= 0 {
		limit = 20
	}
	q := fmt.Sprintf(`
SELECT
  regexp_replace(
    lower(coalesce(payload->>'query', payload->>'name', '')),
    '^(?:.*\.)?([^.]+\.[^.]+)$', '\1'
  ) AS domain,
  COUNT(*) AS count,
  COUNT(DISTINCT agent_id) AS agent_count
FROM events
WHERE event_type IN ('DNS_QUERY','DNS_LOOKUP','NETWORK_DNS')
  AND timestamp > NOW() - INTERVAL '%d hours'
  AND tenant_id = $1
GROUP BY domain
ORDER BY count DESC
LIMIT $2
`, hoursBack)
	rows, err := s.rdb().QueryxContext(ctx, q, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []DNSDomainStat
	for rows.Next() {
		var ds DNSDomainStat
		if err := rows.StructScan(&ds); err != nil {
			return nil, err
		}
		stats = append(stats, ds)
	}
	return stats, rows.Err()
}

// ── Canary Tokens ─────────────────────────────────────────────────────────────

// CreateCanaryToken inserts a new canary token.
func (s *Store) CreateCanaryToken(ctx context.Context, t *models.CanaryToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO canary_tokens (id, tenant_id, name, type, token, deployed_to, description)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, t.ID, t.TenantID, t.Name, t.Type, t.Token, t.DeployedTo, t.Description)
	return err
}

// ListCanaryTokens returns all canary tokens for a tenant.
func (s *Store) ListCanaryTokens(ctx context.Context, tenantID string) ([]models.CanaryToken, error) {
	var tokens []models.CanaryToken
	err := s.rdb().SelectContext(ctx, &tokens,
		`SELECT * FROM canary_tokens WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	return tokens, err
}

// GetCanaryTokenByToken looks up a canary token by its secret token value (no tenant filter).
func (s *Store) GetCanaryTokenByToken(ctx context.Context, token string) (*models.CanaryToken, error) {
	var ct models.CanaryToken
	err := s.db.GetContext(ctx, &ct, `SELECT * FROM canary_tokens WHERE token=$1`, token)
	if err != nil {
		return nil, err
	}
	return &ct, nil
}

// DeleteCanaryToken removes a canary token owned by the given tenant.
func (s *Store) DeleteCanaryToken(ctx context.Context, id, tenantID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM canary_tokens WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// RecordCanaryTrigger increments the trigger count and sets triggered_at.
func (s *Store) RecordCanaryTrigger(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE canary_tokens
		SET trigger_count = trigger_count + 1, triggered_at = NOW()
		WHERE token = $1
	`, token)
	return err
}

// ── Exfil Signals ─────────────────────────────────────────────────────────────

// InsertExfilSignal persists an exfil signal.
func (s *Store) InsertExfilSignal(ctx context.Context, sig *models.ExfilSignal) error {
	detail := sig.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO exfil_signals (id, tenant_id, agent_id, hostname, signal_type, detail, bytes, alert_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, sig.ID, sig.TenantID, sig.AgentID, sig.Hostname, sig.SignalType, []byte(detail), sig.Bytes, sig.AlertID)
	return err
}

// QueryExfilSignals returns exfil signals for a tenant with optional agent filter.
func (s *Store) QueryExfilSignals(ctx context.Context, tenantID, agentID string, limit, offset int) ([]models.ExfilSignal, int, error) {
	if limit <= 0 {
		limit = 100
	}
	args := []interface{}{tenantID}
	where := "WHERE tenant_id=$1"
	n := 2
	if agentID != "" {
		where += fmt.Sprintf(" AND agent_id=$%d", n)
		args = append(args, agentID)
		n++
	}

	var total int
	if err := s.rdb().QueryRowContext(ctx, "SELECT COUNT(*) FROM exfil_signals "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.rdb().QueryxContext(ctx,
		"SELECT * FROM exfil_signals "+where+" ORDER BY detected_at DESC LIMIT $"+fmt.Sprint(n)+" OFFSET $"+fmt.Sprint(n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var sigs []models.ExfilSignal
	for rows.Next() {
		var sig models.ExfilSignal
		if err := rows.StructScan(&sig); err != nil {
			return nil, 0, err
		}
		sigs = append(sigs, sig)
	}
	return sigs, total, rows.Err()
}

// ExfilAgentStats returns per-agent exfil statistics for the last hoursBack hours.
func (s *Store) ExfilAgentStats(ctx context.Context, tenantID string, hoursBack int) ([]models.ExfilAgentStat, error) {
	if hoursBack <= 0 {
		hoursBack = 24
	}
	q := fmt.Sprintf(`
SELECT
  agent_id,
  hostname,
  COUNT(*) AS event_count,
  COALESCE(SUM(bytes), 0) AS total_bytes,
  MAX(detected_at)::TEXT AS last_seen
FROM exfil_signals
WHERE tenant_id=$1
  AND detected_at > NOW() - INTERVAL '%d hours'
GROUP BY agent_id, hostname
ORDER BY total_bytes DESC
`, hoursBack)
	var stats []models.ExfilAgentStat
	err := s.rdb().SelectContext(ctx, &stats, q, tenantID)
	return stats, err
}

// ── Agent Scheduled Tasks ──────────────────────────────────────────────────

func (s *Store) logTaskEvent(ctx context.Context, t *models.AgentTask, action, actor string, detail json.RawMessage) {
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO agent_task_events (id, task_id, tenant_id, agent_id, task_name, task_type, action, actor, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		"ate-"+uuid.New().String(), t.ID, t.TenantID, t.AgentID, t.Name, t.Type, action, actor, []byte(detail))
}

func (s *Store) CreateAgentTask(ctx context.Context, t *models.AgentTask, actor string) error {
	payload := t.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_tasks (id, tenant_id, agent_id, name, type, schedule, payload, status, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
		t.ID, t.TenantID, t.AgentID, t.Name, t.Type, t.Schedule, []byte(payload), actor)
	if err != nil {
		return err
	}
	t.CreatedBy = actor
	s.logTaskEvent(ctx, t, "created", actor, json.RawMessage(`{"schedule":"`+t.Schedule+`"}`))
	return nil
}

func (s *Store) ListAgentTasks(ctx context.Context, tenantID, agentID, status string) ([]models.AgentTask, error) {
	q := `SELECT * FROM agent_tasks WHERE tenant_id=$1 AND status != 'deleted'`
	args := []interface{}{tenantID}
	if agentID != "" {
		q += ` AND agent_id=$2`
		args = append(args, agentID)
	}
	if status != "" {
		q += fmt.Sprintf(` AND status=$%d`, len(args)+1)
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC`
	var tasks []models.AgentTask
	return tasks, s.rdb().SelectContext(ctx, &tasks, q, args...)
}

func (s *Store) GetAgentTask(ctx context.Context, id, tenantID string) (*models.AgentTask, error) {
	var t models.AgentTask
	err := s.rdb().GetContext(ctx, &t, `SELECT * FROM agent_tasks WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) UpdateAgentTask(ctx context.Context, id, tenantID, actor string, name, schedule, status string, payload json.RawMessage) (*models.AgentTask, error) {
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE agent_tasks SET name=$1, schedule=$2, status=$3, payload=$4, updated_at=NOW()
		WHERE id=$5 AND tenant_id=$6`,
		name, schedule, status, []byte(payload), id, tenantID)
	if err != nil {
		return nil, err
	}
	t, err := s.GetAgentTask(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	action := "updated"
	if status == "paused" {
		action = "paused"
	} else if status == "active" {
		action = "resumed"
	}
	s.logTaskEvent(ctx, t, action, actor, json.RawMessage(`{"schedule":"`+schedule+`","status":"`+status+`"}`))
	return t, nil
}

func (s *Store) DeleteAgentTask(ctx context.Context, id, tenantID, actor string) error {
	t, err := s.GetAgentTask(ctx, id, tenantID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE agent_tasks SET status='deleted', updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return err
	}
	s.logTaskEvent(ctx, t, "deleted", actor, json.RawMessage("{}"))
	return nil
}

func (s *Store) ListTaskEvents(ctx context.Context, tenantID, agentID, taskID string, limit, offset int) ([]models.AgentTaskEvent, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	base := `FROM agent_task_events WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	if agentID != "" {
		base += ` AND agent_id=$2`
		args = append(args, agentID)
	}
	if taskID != "" {
		base += fmt.Sprintf(` AND task_id=$%d`, len(args)+1)
		args = append(args, taskID)
	}
	var total int
	_ = s.rdb().QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total)
	dataArgs := append(args, limit, offset)
	var events []models.AgentTaskEvent
	err := s.rdb().SelectContext(ctx, &events,
		"SELECT * "+base+fmt.Sprintf(` ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2),
		dataArgs...)
	return events, total, err
}

// LogTaskRunEvent records an on-demand execution trigger in the task audit log.
func (s *Store) LogTaskRunEvent(ctx context.Context, t *models.AgentTask, actor string) error {
	s.logTaskEvent(ctx, t, "executed", actor, json.RawMessage(`{"trigger":"manual"}`))
	return nil
}

// nextRunAfter computes the next execution time from a cron-like schedule string.
// Handles @hourly, @daily, @weekly, @monthly, and Nh/Nm shorthand.
// Returns zero time for unknown/empty schedules (one-shot).
func nextRunAfter(schedule string, from time.Time) time.Time {
	switch schedule {
	case "", "@once":
		return time.Time{}
	case "@hourly":
		return from.Add(time.Hour)
	case "@daily", "@midnight":
		return from.Add(24 * time.Hour)
	case "@weekly":
		return from.Add(7 * 24 * time.Hour)
	case "@monthly":
		return from.AddDate(0, 1, 0)
	}
	// Simple interval shorthand: "30m", "6h", "1h30m" etc.
	if d, err := time.ParseDuration(schedule); err == nil && d > 0 {
		return from.Add(d)
	}
	// For full cron expressions fall back to 24h to avoid tight loops.
	if len(strings.Fields(schedule)) == 5 {
		return from.Add(24 * time.Hour)
	}
	return time.Time{}
}

// ClaimDueAgentTasks returns tasks that are due for the given agent and
// atomically marks them as in-flight by advancing next_run_at.
func (s *Store) ClaimDueAgentTasks(ctx context.Context, agentID string) ([]models.AgentTask, error) {
	var tasks []models.AgentTask
	err := s.rdb().SelectContext(ctx, &tasks, `
		SELECT * FROM agent_tasks
		WHERE agent_id = $1
		  AND status   = 'active'
		  AND (next_run_at IS NULL OR next_run_at <= NOW())
		ORDER BY next_run_at ASC NULLS FIRST`,
		agentID)
	if err != nil || len(tasks) == 0 {
		return tasks, err
	}
	now := time.Now()
	for _, t := range tasks {
		next := nextRunAfter(t.Schedule, now)
		if next.IsZero() {
			// One-shot: mark completed so it won't be re-delivered.
			_, _ = s.db.ExecContext(ctx,
				`UPDATE agent_tasks SET last_run_at=$1, next_run_at=NULL, status='completed', updated_at=NOW() WHERE id=$2`,
				now, t.ID)
		} else {
			_, _ = s.db.ExecContext(ctx,
				`UPDATE agent_tasks SET last_run_at=$1, next_run_at=$2, updated_at=NOW() WHERE id=$3`,
				now, next, t.ID)
		}
	}
	return tasks, nil
}

// RecordAgentTaskResult logs an execution result reported by the agent.
func (s *Store) RecordAgentTaskResult(ctx context.Context, taskID, status, output, errMsg string) error {
	t, err := s.db.ExecContext(ctx,
		`UPDATE agent_tasks SET last_run_at=NOW(), updated_at=NOW() WHERE id=$1`,
		taskID)
	if err != nil {
		return err
	}
	if n, _ := t.RowsAffected(); n == 0 {
		return nil
	}
	detail, _ := json.Marshal(map[string]string{"status": status, "output": truncate(output, 512), "error": errMsg})
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO agent_task_events (id, task_id, tenant_id, agent_id, task_name, task_type, action, actor, detail)
		SELECT $1, id, tenant_id, agent_id, name, type, 'executed', 'agent', $2
		FROM agent_tasks WHERE id=$3`,
		"ate-"+uuid.New().String(), json.RawMessage(detail), taskID)
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// TriggerAgentTaskNow forces a task to run on the agent's next heartbeat
// by setting next_run_at to the current time.
func (s *Store) TriggerAgentTaskNow(ctx context.Context, id, tenantID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agent_tasks SET next_run_at=NOW(), updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='active'`,
		id, tenantID)
	return err
}

// ── Attack Surface ────────────────────────────────────────────────────────────

// OpenPort is a listening port entry in the attack surface.
type OpenPort struct {
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	Process          string `json:"process"`
	PID              int    `json:"pid"`
	InternetReachable bool  `json:"internet_reachable"`
}

// ExposedVuln is a vulnerability that has an associated open port.
type ExposedVuln struct {
	CveID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	PackageName string `json:"package_name"`
}

// AttackSurfaceSnapshot is the synthesised attack surface for one agent.
type AttackSurfaceSnapshot struct {
	ID              string        `json:"id"          db:"id"`
	TenantID        string        `json:"tenant_id"   db:"tenant_id"`
	AgentID         string        `json:"agent_id"    db:"agent_id"`
	SnapshotAt      time.Time     `json:"snapshot_at" db:"snapshot_at"`
	OpenPorts       json.RawMessage `json:"open_ports"   db:"open_ports"`
	ExposedVulns    json.RawMessage `json:"exposed_vulns" db:"exposed_vulns"`
	RiskScore       int16         `json:"risk_score"  db:"risk_score"`
	Hostname        string        `json:"hostname,omitempty" db:"hostname"`
	OpenPortCount   int           `json:"open_port_count,omitempty"  db:"open_port_count"`
	ExposedVulnCount int          `json:"exposed_vuln_count,omitempty" db:"exposed_vuln_count"`
}

// OrgAttackSurfaceAgent is one row in the org-wide roll-up.
type OrgAttackSurfaceAgent struct {
	AgentID          string    `json:"agent_id"           db:"agent_id"`
	Hostname         string    `json:"hostname"           db:"hostname"`
	IP               string    `json:"ip"                 db:"ip"`
	RiskScore        int16     `json:"risk_score"         db:"risk_score"`
	OpenPortCount    int       `json:"open_port_count"    db:"open_port_count"`
	ExposedVulnCount int       `json:"exposed_vuln_count" db:"exposed_vuln_count"`
	SnapshotAt       time.Time `json:"snapshot_at"        db:"snapshot_at"`
}

// UpsertAttackSurfaceSnapshot writes a fresh snapshot for one agent.
func (s *Store) UpsertAttackSurfaceSnapshot(ctx context.Context, snap *AttackSurfaceSnapshot) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO attack_surface_snapshots
		    (id, tenant_id, agent_id, snapshot_at, open_ports, exposed_vulns, risk_score)
		VALUES ($1,$2,$3,NOW(),$4,$5,$6)`,
		snap.ID, snap.TenantID, snap.AgentID,
		snap.OpenPorts, snap.ExposedVulns, snap.RiskScore)
	return err
}

// GetAgentAttackSurface returns the most-recent snapshot for one agent,
// enriched with open ports and exposed vulns.
func (s *Store) GetAgentAttackSurface(ctx context.Context, agentID string) (*AttackSurfaceSnapshot, error) {
	var snap AttackSurfaceSnapshot
	err := s.rdb().GetContext(ctx, &snap, `
		SELECT id, tenant_id, agent_id, snapshot_at, open_ports, exposed_vulns, risk_score
		FROM attack_surface_snapshots
		WHERE agent_id=$1
		ORDER BY snapshot_at DESC LIMIT 1`, agentID)
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

// GetOrgAttackSurface returns the top agents by exposed-vuln count.
func (s *Store) GetOrgAttackSurface(ctx context.Context, internetOnly bool) ([]OrgAttackSurfaceAgent, error) {
	q := `
		SELECT s.agent_id,
		       COALESCE(a.hostname, s.agent_id) AS hostname,
		       COALESCE(a.ip, '')               AS ip,
		       COALESCE(a.risk_score, 0)        AS risk_score,
		       jsonb_array_length(s.open_ports)    AS open_port_count,
		       jsonb_array_length(s.exposed_vulns) AS exposed_vuln_count,
		       s.snapshot_at
		FROM attack_surface_snapshots s
		LEFT JOIN agents a ON a.id = s.agent_id
		WHERE s.snapshot_at = (
		    SELECT MAX(s2.snapshot_at) FROM attack_surface_snapshots s2
		    WHERE s2.agent_id = s.agent_id
		)`
	if internetOnly {
		q += ` AND jsonb_path_exists(s.open_ports, '$[*] ? (@.internet_reachable == true)')`
	}
	q += ` ORDER BY exposed_vuln_count DESC, open_port_count DESC LIMIT 50`

	var out []OrgAttackSurfaceAgent
	err := s.rdb().SelectContext(ctx, &out, q)
	return out, err
}

// ComputeAgentAttackSurface derives open ports + exposed vulns from events + vulnerabilities tables.
// Called by the background scanner — does NOT write to the DB.
func (s *Store) ComputeAgentAttackSurface(ctx context.Context, agentID string) ([]OpenPort, []ExposedVuln, error) {
	// Open ports: recent NET_ACCEPT events in the last hour, grouped by dst_port
	type portRow struct {
		DstPort   int    `db:"dst_port"`
		Protocol  string `db:"protocol"`
		Comm      string `db:"comm"`
		PID       int    `db:"pid"`
		MaxSrcIP  string `db:"max_src_ip"`
	}
	var portRows []portRow
	err := s.rdb().SelectContext(ctx, &portRows, `
		SELECT
		    (payload->>'dst_port')::int              AS dst_port,
		    COALESCE(payload->>'protocol', 'tcp')    AS protocol,
		    COALESCE(payload->>'comm', '')            AS comm,
		    COALESCE((payload->>'pid')::int, 0)      AS pid,
		    MAX(payload->>'src_ip')                  AS max_src_ip
		FROM events
		WHERE agent_id = $1
		  AND event_type = 'NET_ACCEPT'
		  AND timestamp > NOW() - INTERVAL '1 hour'
		  AND (payload->>'dst_port') IS NOT NULL
		  AND (payload->>'dst_port')::int > 0
		GROUP BY dst_port, protocol, comm, pid
		ORDER BY dst_port ASC
		LIMIT 100`, agentID)
	if err != nil {
		return nil, nil, err
	}

	openPorts := make([]OpenPort, 0, len(portRows))
	portSet := map[int]bool{}
	for _, r := range portRows {
		internet := !isPrivateIP(r.MaxSrcIP)
		openPorts = append(openPorts, OpenPort{
			Port: r.DstPort, Protocol: r.Protocol,
			Process: r.Comm, PID: r.PID,
			InternetReachable: internet,
		})
		portSet[r.DstPort] = true
	}

	// Exposed vulns: vulnerabilities whose package is running on an open port.
	// Match heuristically: well-known service→port mapping.
	vulns, err := s.QueryVulnerabilities(ctx, agentID, 200, 0)
	if err != nil {
		return openPorts, nil, err
	}

	sevOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
	exposed := make([]ExposedVuln, 0)
	for _, v := range vulns {
		port := servicePort(v.PackageName)
		if port == 0 || !portSet[port] {
			// If no known port mapping, include when any port is open for critical/high
			if sevOrder[v.Severity] < 3 {
				continue
			}
			if len(openPorts) == 0 {
				continue
			}
			port = openPorts[0].Port
		}
		exposed = append(exposed, ExposedVuln{
			CveID:       v.CveID,
			Severity:    v.Severity,
			Port:        port,
			Service:     v.PackageName,
			PackageName: v.PackageName,
		})
	}
	return openPorts, exposed, nil
}

// isPrivateIP returns true for RFC-1918 / loopback / link-local addresses.
func isPrivateIP(ip string) bool {
	if ip == "" {
		return true
	}
	private := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "127.", "::1", "fc", "fd"}
	for _, pfx := range private {
		if strings.HasPrefix(ip, pfx) {
			return true
		}
	}
	return false
}

// servicePort maps well-known package names to their default port.
func servicePort(pkg string) int {
	p := strings.ToLower(pkg)
	m := map[string]int{
		"nginx": 80, "apache2": 80, "apache": 80, "httpd": 80,
		"nodejs": 3000, "node": 3000,
		"openssh-server": 22, "openssh": 22, "sshd": 22,
		"mysql-server": 3306, "mysql": 3306,
		"postgresql": 5432, "postgres": 5432,
		"redis-server": 6379, "redis": 6379,
		"mongodb": 27017, "mongod": 27017,
		"tomcat": 8080, "tomcat9": 8080,
		"docker": 2375, "dockerd": 2375,
		"elasticsearch": 9200, "kibana": 5601,
		"memcached": 11211, "rabbitmq": 5672,
		"vsftpd": 21, "proftpd": 21, "pure-ftpd": 21,
		"postfix": 25, "sendmail": 25, "exim4": 25,
		"bind9": 53, "named": 53,
		"ntp": 123, "ntpd": 123,
		"smbd": 445, "nmbd": 445,
	}
	for k, v := range m {
		if strings.Contains(p, k) {
			return v
		}
	}
	return 0
}

// ── Risk Score History ────────────────────────────────────────────────────────

// RiskTrendPoint is a single day's average score in the trend series.
type RiskTrendPoint struct {
	Date   string `json:"date"`
	Score  int16  `json:"score"`
	Agents int16  `json:"agents"`
	Users  int16  `json:"users"`
}

// OrgThreatScore is the full response for GET /xdr/threat-score.
type OrgThreatScore struct {
	OrgScore        int16                    `json:"org_score"`
	ScoreDelta24h   int                      `json:"score_delta_24h"`
	Trend           []RiskTrendPoint         `json:"trend"`
	TopAgents       []models.Agent           `json:"top_agents"`
	TopUsers        []models.IdentityRecord  `json:"top_users"`
	FactorBreakdown map[string]int           `json:"factor_breakdown"`
}

// RecordRiskScoreSnapshot inserts one risk score snapshot row.
func (s *Store) RecordRiskScoreSnapshot(ctx context.Context, tenantID, entityType, entityID string, score int16, factors json.RawMessage) error {
	if factors == nil {
		factors = json.RawMessage(`[]`)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO risk_score_history (id, tenant_id, entity_type, entity_id, score, factors)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		"rsh-"+uuid.New().String(), tenantID, entityType, entityID, score, factors)
	return err
}

// ListAllRiskableAgents returns every agent with a non-zero risk score.
func (s *Store) ListAllRiskableAgents(ctx context.Context) ([]models.Agent, error) {
	var out []models.Agent
	err := s.rdb().SelectContext(ctx, &out,
		`SELECT id, hostname, ip, risk_score, risk_factors, risk_updated_at
		 FROM agents WHERE risk_score > 0`)
	return out, err
}

// ListAllRiskableIdentities returns every identity with a non-zero risk score.
func (s *Store) ListAllRiskableIdentities(ctx context.Context) ([]models.IdentityRecord, error) {
	var out []models.IdentityRecord
	err := s.rdb().SelectContext(ctx, &out,
		`SELECT id, canonical_uid, display_name, risk_score, risk_factors
		 FROM identity_graph WHERE risk_score > 0`)
	return out, err
}

// GetOrgThreatScore computes the org-wide threat score summary.
func (s *Store) GetOrgThreatScore(ctx context.Context, tenantID string, days int) (*OrgThreatScore, error) {
	if days <= 0 {
		days = 30
	}

	// Current live scores
	var agentAvg, userAvg float64
	_ = s.rdb().GetContext(ctx, &agentAvg, `SELECT COALESCE(AVG(risk_score),0) FROM agents WHERE risk_score > 0`)
	_ = s.rdb().GetContext(ctx, &userAvg, `SELECT COALESCE(AVG(risk_score),0) FROM identity_graph WHERE risk_score > 0`)
	orgScore := int16((agentAvg + userAvg) / 2)

	// 24 h delta: compare today's avg vs yesterday's avg from history
	var prevScore float64
	_ = s.rdb().GetContext(ctx, &prevScore, `
		SELECT COALESCE(AVG(score),0) FROM risk_score_history
		WHERE tenant_id=$1
		  AND recorded_at BETWEEN NOW()-INTERVAL '48 hours' AND NOW()-INTERVAL '24 hours'`,
		tenantID)
	delta := int(orgScore) - int(prevScore)

	// Daily trend from history
	type trendRow struct {
		Day        string  `db:"day"`
		EntityType string  `db:"entity_type"`
		AvgScore   float64 `db:"avg_score"`
	}
	var trendRows []trendRow
	_ = s.rdb().SelectContext(ctx, &trendRows, `
		SELECT to_char(date_trunc('day', recorded_at), 'YYYY-MM-DD') AS day,
		       entity_type,
		       AVG(score) AS avg_score
		FROM risk_score_history
		WHERE tenant_id=$1 AND recorded_at > NOW() - make_interval(days => $2)
		GROUP BY day, entity_type
		ORDER BY day ASC`,
		tenantID, days)

	// Merge agent/user rows into combined trend points
	trendMap := map[string]*RiskTrendPoint{}
	for _, r := range trendRows {
		pt := trendMap[r.Day]
		if pt == nil {
			pt = &RiskTrendPoint{Date: r.Day}
			trendMap[r.Day] = pt
		}
		switch r.EntityType {
		case "agent":
			pt.Agents = int16(r.AvgScore)
		case "user":
			pt.Users = int16(r.AvgScore)
		}
		pt.Score = int16((float64(pt.Agents) + float64(pt.Users)) / 2)
	}
	trend := make([]RiskTrendPoint, 0, len(trendMap))
	for _, pt := range trendMap {
		trend = append(trend, *pt)
	}
	// sort by date
	for i := 1; i < len(trend); i++ {
		for j := i; j > 0 && trend[j].Date < trend[j-1].Date; j-- {
			trend[j], trend[j-1] = trend[j-1], trend[j]
		}
	}

	// Top agents + users (existing methods)
	topAgents, _ := s.ListTopRiskAgents(ctx, 10)
	topUsers, _ := s.TopRiskyIdentities(ctx, 10)

	// Factor breakdown — count by factor name across both tables
	breakdown := map[string]int{}
	type factorRow struct {
		Factor string `db:"factor"`
		Cnt    int    `db:"cnt"`
	}
	var agentFactors, userFactors []factorRow
	_ = s.rdb().SelectContext(ctx, &agentFactors, `
		SELECT f.value::text AS factor, COUNT(*) AS cnt
		FROM agents, jsonb_array_elements_text(risk_factors) f
		WHERE risk_score > 0
		GROUP BY factor`)
	_ = s.rdb().SelectContext(ctx, &userFactors, `
		SELECT f.value::text AS factor, COUNT(*) AS cnt
		FROM identity_graph, jsonb_array_elements_text(risk_factors) f
		WHERE risk_score > 0
		GROUP BY factor`)
	for _, r := range agentFactors {
		breakdown[r.Factor] += r.Cnt
	}
	for _, r := range userFactors {
		breakdown[r.Factor] += r.Cnt
	}

	if topAgents == nil {
		topAgents = []models.Agent{}
	}
	if topUsers == nil {
		topUsers = []models.IdentityRecord{}
	}
	if trend == nil {
		trend = []RiskTrendPoint{}
	}

	return &OrgThreatScore{
		OrgScore:        orgScore,
		ScoreDelta24h:   delta,
		Trend:           trend,
		TopAgents:       topAgents,
		TopUsers:        topUsers,
		FactorBreakdown: breakdown,
	}, nil
}

// GetEntityRiskHistory returns daily-averaged score history for one entity.
func (s *Store) GetEntityRiskHistory(ctx context.Context, entityID, entityType string, days int) ([]RiskTrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	type row struct {
		Day   string  `db:"day"`
		Score float64 `db:"avg_score"`
	}
	var rows []row
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT to_char(date_trunc('day', recorded_at), 'YYYY-MM-DD') AS day,
		       AVG(score) AS avg_score
		FROM risk_score_history
		WHERE entity_id=$1 AND entity_type=$2
		  AND recorded_at > NOW() - make_interval(days => $3)
		GROUP BY day ORDER BY day ASC`,
		entityID, entityType, days)
	if err != nil {
		return nil, err
	}
	out := make([]RiskTrendPoint, len(rows))
	for i, r := range rows {
		out[i] = RiskTrendPoint{Date: r.Day, Score: int16(r.Score)}
	}
	return out, nil
}

// ── Lateral Movement Graph ────────────────────────────────────────────────────

// LateralGraphNode is a host node in the tenant-wide lateral movement graph.
type LateralGraphNode struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	RiskScore  int16  `json:"risk_score"`
	AgentID    string `json:"agent_id"`
	AlertCount int    `json:"alert_count"`
}

// LateralGraphEdge represents a connection between two hosts.
type LateralGraphEdge struct {
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Count     int       `json:"count"`
	Protocols []string  `json:"protocols"`
	LastSeen  time.Time `json:"last_seen"`
}

// LateralGraph is the full tenant-wide lateral movement graph response.
type LateralGraph struct {
	Nodes []LateralGraphNode `json:"nodes"`
	Edges []LateralGraphEdge `json:"edges"`
}

// GetLateralGraph returns a tenant-wide lateral movement graph.
// Edges are derived from users with shared login sessions across multiple agents.
// Nodes are all agents that appear in at least one edge or have open alerts.
func (s *Store) GetLateralGraph(ctx context.Context, hours, minConnections int) (*LateralGraph, error) {
	if hours <= 0 || hours > 24*7 {
		hours = 24
	}
	if minConnections <= 0 {
		minConnections = 1
	}

	type edgeRow struct {
		Src      string    `db:"src"`
		Dst      string    `db:"dst"`
		Count    int       `db:"cnt"`
		LastSeen time.Time `db:"last_seen"`
	}
	var rawEdges []edgeRow
	err := s.rdb().SelectContext(ctx, &rawEdges, `
		SELECT ls1.agent_id AS src, ls2.agent_id AS dst,
		       COUNT(*) AS cnt,
		       MAX(GREATEST(ls1.logged_in_at, ls2.logged_in_at)) AS last_seen
		FROM login_sessions ls1
		JOIN login_sessions ls2
		  ON ls1.user_uid = ls2.user_uid AND ls1.agent_id < ls2.agent_id
		WHERE ls1.logged_in_at > NOW() - make_interval(hours => $1)
		  AND ls2.logged_in_at > NOW() - make_interval(hours => $1)
		GROUP BY ls1.agent_id, ls2.agent_id
		HAVING COUNT(*) >= $2`,
		hours, minConnections)
	if err != nil {
		return nil, err
	}

	agentSet := map[string]bool{}
	var edges []LateralGraphEdge
	for _, e := range rawEdges {
		agentSet[e.Src] = true
		agentSet[e.Dst] = true
		edges = append(edges, LateralGraphEdge{
			Src:       e.Src,
			Dst:       e.Dst,
			Count:     e.Count,
			Protocols: []string{"auth"},
			LastSeen:  e.LastSeen,
		})
	}

	type nodeRow struct {
		ID         string `db:"id"`
		Hostname   string `db:"hostname"`
		IP         string `db:"ip"`
		RiskScore  int16  `db:"risk_score"`
		AlertCount int    `db:"alert_count"`
	}
	var nodeRows []nodeRow
	err = s.rdb().SelectContext(ctx, &nodeRows, `
		SELECT a.id, a.hostname, a.ip,
		       COALESCE(a.risk_score, 0) AS risk_score,
		       COUNT(al.id) FILTER (WHERE al.status='OPEN') AS alert_count
		FROM agents a
		LEFT JOIN alerts al ON al.agent_id = a.id AND al.status = 'OPEN'
		GROUP BY a.id, a.hostname, a.ip, a.risk_score
		ORDER BY a.last_seen DESC
		LIMIT 300`)
	if err != nil {
		return nil, err
	}

	var nodes []LateralGraphNode
	for _, n := range nodeRows {
		if agentSet[n.ID] || n.AlertCount > 0 {
			nodes = append(nodes, LateralGraphNode{
				ID: n.ID, Hostname: n.Hostname, IP: n.IP,
				RiskScore: n.RiskScore, AgentID: n.ID, AlertCount: n.AlertCount,
			})
		}
	}
	// If no edges found, still return top-risk agents so the page isn't empty.
	if len(nodes) == 0 {
		for i, n := range nodeRows {
			if i >= 50 {
				break
			}
			nodes = append(nodes, LateralGraphNode{
				ID: n.ID, Hostname: n.Hostname, IP: n.IP,
				RiskScore: n.RiskScore, AgentID: n.ID, AlertCount: n.AlertCount,
			})
		}
	}
	if nodes == nil {
		nodes = []LateralGraphNode{}
	}
	if edges == nil {
		edges = []LateralGraphEdge{}
	}
	return &LateralGraph{Nodes: nodes, Edges: edges}, nil
}

// ── Forensic Timeline ─────────────────────────────────────────────────────────

// ForensicEvent is a single event entry in the forensic timeline.
type ForensicEvent struct {
	ID        string          `json:"id"         db:"id"`
	Type      string          `json:"type"       db:"event_type"`
	Timestamp time.Time       `json:"timestamp"  db:"timestamp"`
	AgentID   string          `json:"agent_id"   db:"agent_id"`
	Hostname  string          `json:"hostname"   db:"hostname"`
	Severity  int16           `json:"severity"   db:"severity"`
	Payload   json.RawMessage `json:"payload"    db:"payload"`
	AlertID   string          `json:"alert_id,omitempty" db:"alert_id"`
	Source    string          `json:"source"     db:"-"`
}

// ForensicTimelineResult is the paginated response for a forensic timeline query.
type ForensicTimelineResult struct {
	Events  []ForensicEvent `json:"events"`
	Total   int             `json:"total"`
	HasMore bool            `json:"has_more"`
	Cursor  string          `json:"cursor,omitempty"`
}

// ForensicOpts holds optional filters for forensic timeline queries.
type ForensicOpts struct {
	After  *time.Time
	Before *time.Time
	Types  []string
	Limit  int
	Offset int
}

func (s *Store) forensicLabel(e *ForensicEvent) string {
	if e.AlertID != "" {
		return "xdr"
	}
	switch e.Type {
	case "NET_CONNECT", "NET_ACCEPT", "DNS_QUERY":
		return "xdr"
	case "LOGIN", "LOGOUT", "AUTH_FAIL":
		return "identity"
	}
	return "edr"
}

// GetIncidentForensicTimeline returns a unified event stream for all agents
// involved in an incident, ±5 min around the incident window.
func (s *Store) GetIncidentForensicTimeline(ctx context.Context, incidentID, tenantID string, opts ForensicOpts) (*ForensicTimelineResult, error) {
	var inc struct {
		AgentIDs  pq.StringArray `db:"agent_ids"`
		FirstSeen time.Time      `db:"first_seen"`
		LastSeen  time.Time      `db:"last_seen"`
	}
	if err := s.rdb().GetContext(ctx, &inc,
		`SELECT agent_ids, first_seen, last_seen FROM incidents WHERE id=$1 AND tenant_id=$2`,
		incidentID, tenantID); err != nil {
		return nil, err
	}

	windowStart := inc.FirstSeen.Add(-5 * time.Minute)
	windowEnd := inc.LastSeen.Add(5 * time.Minute)
	if opts.After != nil {
		windowStart = *opts.After
	}
	if opts.Before != nil {
		windowEnd = *opts.Before
	}

	limit := opts.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	args := []interface{}{pq.Array([]string(inc.AgentIDs)), windowStart, windowEnd}
	q := `SELECT id, event_type, timestamp, agent_id, hostname, severity, payload, alert_id
	      FROM events
	      WHERE agent_id = ANY($1) AND timestamp BETWEEN $2 AND $3`
	if len(opts.Types) > 0 {
		args = append(args, pq.Array(opts.Types))
		q += fmt.Sprintf(` AND event_type = ANY($%d)`, len(args))
	}
	q += fmt.Sprintf(` ORDER BY timestamp ASC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, limit+1, opts.Offset)

	var rows []ForensicEvent
	if err := s.rdb().SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, err
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	var cursor string
	if hasMore && len(rows) > 0 {
		cursor = rows[len(rows)-1].Timestamp.Format(time.RFC3339Nano)
	}
	for i := range rows {
		rows[i].Source = s.forensicLabel(&rows[i])
	}
	if rows == nil {
		rows = []ForensicEvent{}
	}
	return &ForensicTimelineResult{Events: rows, Total: len(rows), HasMore: hasMore, Cursor: cursor}, nil
}

// GetAgentForensicTimeline returns a forensic timeline scoped to a single agent.
func (s *Store) GetAgentForensicTimeline(ctx context.Context, agentID string, opts ForensicOpts) (*ForensicTimelineResult, error) {
	windowStart := time.Now().Add(-24 * time.Hour)
	windowEnd := time.Now()
	if opts.After != nil {
		windowStart = *opts.After
	}
	if opts.Before != nil {
		windowEnd = *opts.Before
	}

	limit := opts.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	args := []interface{}{agentID, windowStart, windowEnd}
	q := `SELECT id, event_type, timestamp, agent_id, hostname, severity, payload, alert_id
	      FROM events
	      WHERE agent_id = $1 AND timestamp BETWEEN $2 AND $3`
	if len(opts.Types) > 0 {
		args = append(args, pq.Array(opts.Types))
		q += fmt.Sprintf(` AND event_type = ANY($%d)`, len(args))
	}
	q += fmt.Sprintf(` ORDER BY timestamp ASC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, limit+1, opts.Offset)

	var rows []ForensicEvent
	if err := s.rdb().SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, err
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	var cursor string
	if hasMore && len(rows) > 0 {
		cursor = rows[len(rows)-1].Timestamp.Format(time.RFC3339Nano)
	}
	for i := range rows {
		rows[i].Source = s.forensicLabel(&rows[i])
	}
	if rows == nil {
		rows = []ForensicEvent{}
	}
	return &ForensicTimelineResult{Events: rows, Total: len(rows), HasMore: hasMore, Cursor: cursor}, nil
}
