// internal/store/store.go
// Repository layer — all database queries live here.

package store

import (
	"context"
	"encoding/json"
	"fmt"
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

// ─── Agents ───────────────────────────────────────────────────────────────────

func (s *Store) UpsertAgent(ctx context.Context, a *models.Agent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen, is_online, config_ver)
		VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW(),TRUE,$7)
		ON CONFLICT (id) DO UPDATE SET
			hostname   = EXCLUDED.hostname,
			os         = EXCLUDED.os,
			os_version = EXCLUDED.os_version,
			ip         = EXCLUDED.ip,
			agent_ver  = EXCLUDED.agent_ver,
			last_seen  = NOW(),
			is_online  = TRUE
	`, a.ID, a.Hostname, a.OS, a.OSVersion, a.IP, a.AgentVer, a.ConfigVer)
	return err
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
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE agent_id=$1 AND timestamp >= $2`,
		agentID, since,
	).Scan(&n)
	return n, err
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (s *Store) InsertAlert(ctx context.Context, a *models.Alert) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts
		  (id, title, description, severity, status, rule_id, rule_name, mitre_ids, event_ids, agent_id, hostname, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			last_seen  = NOW(),
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
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO rules (id, name, description, enabled, severity, event_types, conditions, mitre_ids, author, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			name        = EXCLUDED.name,
			description = EXCLUDED.description,
			enabled     = EXCLUDED.enabled,
			severity    = EXCLUDED.severity,
			event_types = EXCLUDED.event_types,
			conditions  = EXCLUDED.conditions,
			mitre_ids   = EXCLUDED.mitre_ids,
			updated_at  = NOW()
	`, r.ID, r.Name, r.Description, r.Enabled, r.Severity,
		pq.Array(r.EventTypes), conds, pq.Array(r.MitreIDs), r.Author)
	return err
}

func (s *Store) DeleteRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id=$1`, id)
	return err
}
