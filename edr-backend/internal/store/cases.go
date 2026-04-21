// internal/store/cases.go — Case management persistence.

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/youredr/edr-backend/internal/models"
)

// ── Cases ─────────────────────────────────────────────────────────────────────

func (s *Store) ListCases(ctx context.Context, status string, limit, offset int) ([]models.Case, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	countQ := `SELECT COUNT(*) FROM cases`
	listQ := `SELECT id, title, description, status, severity, assignee, tags,
	                 mitre_ids, alert_count, created_by, created_at, updated_at, closed_at
	          FROM cases`

	var args []interface{}
	var where string
	if status != "" {
		args = append(args, status)
		where = fmt.Sprintf(" WHERE status = $%d", len(args))
	}

	var total int
	if err := s.db.QueryRowContext(ctx, countQ+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		listQ+where+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var cases []models.Case
	for rows.Next() {
		var c models.Case
		if err := rows.Scan(
			&c.ID, &c.Title, &c.Description, &c.Status, &c.Severity, &c.Assignee,
			pq.Array(&c.Tags), pq.Array(&c.MitreIDs), &c.AlertCount,
			&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.ClosedAt,
		); err != nil {
			return nil, 0, err
		}
		cases = append(cases, c)
	}
	return cases, total, rows.Err()
}

func (s *Store) GetCase(ctx context.Context, id string) (*models.Case, error) {
	var c models.Case
	err := s.db.QueryRowContext(ctx,
		`SELECT id, title, description, status, severity, assignee, tags,
		        mitre_ids, alert_count, created_by, created_at, updated_at, closed_at
		 FROM cases WHERE id = $1`, id,
	).Scan(
		&c.ID, &c.Title, &c.Description, &c.Status, &c.Severity, &c.Assignee,
		pq.Array(&c.Tags), pq.Array(&c.MitreIDs), &c.AlertCount,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.ClosedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) CreateCase(ctx context.Context, c *models.Case) error {
	if c.ID == "" {
		c.ID = "case-" + uuid.New().String()
	}
	now := time.Now().UTC()
	c.CreatedAt = now
	c.UpdatedAt = now
	if c.Status == "" {
		c.Status = models.CaseStatusOpen
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cases (id, title, description, status, severity, assignee, tags,
		                    mitre_ids, alert_count, created_by, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		c.ID, c.Title, c.Description, c.Status, c.Severity, c.Assignee,
		pq.Array(c.Tags), pq.Array(c.MitreIDs), c.AlertCount,
		c.CreatedBy, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (s *Store) UpdateCase(ctx context.Context, c *models.Case) error {
	c.UpdatedAt = time.Now().UTC()
	if c.Status == models.CaseStatusClosed || c.Status == models.CaseStatusResolved {
		now := time.Now().UTC()
		c.ClosedAt = &now
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE cases SET title=$2, description=$3, status=$4, severity=$5, assignee=$6,
		                  tags=$7, mitre_ids=$8, updated_at=$9, closed_at=$10
		 WHERE id=$1`,
		c.ID, c.Title, c.Description, c.Status, c.Severity, c.Assignee,
		pq.Array(c.Tags), pq.Array(c.MitreIDs), c.UpdatedAt, c.ClosedAt,
	)
	return err
}

func (s *Store) DeleteCase(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM cases WHERE id = $1`, id)
	return err
}

// ── Case Alerts ───────────────────────────────────────────────────────────────

func (s *Store) ListCaseAlerts(ctx context.Context, caseID string) ([]models.Alert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.title, a.description, a.severity, a.status, a.rule_id, a.rule_name,
		        a.mitre_ids, a.event_ids, a.agent_id, a.hostname, a.first_seen, a.last_seen,
		        a.assignee, a.notes, a.hit_count, a.incident_id
		 FROM alerts a
		 JOIN case_alerts ca ON ca.alert_id = a.id
		 WHERE ca.case_id = $1
		 ORDER BY a.last_seen DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		if err := rows.Scan(
			&a.ID, &a.Title, &a.Description, &a.Severity, &a.Status,
			&a.RuleID, &a.RuleName, pq.Array(&a.MitreIDs), pq.Array(&a.EventIDs),
			&a.AgentID, &a.Hostname, &a.FirstSeen, &a.LastSeen,
			&a.Assignee, &a.Notes, &a.HitCount, &a.IncidentID,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (s *Store) LinkAlertToCase(ctx context.Context, caseID, alertID, linkedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO case_alerts (case_id, alert_id, linked_by)
		 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		caseID, alertID, linkedBy)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE cases SET alert_count = (
		     SELECT COUNT(*) FROM case_alerts WHERE case_id = $1
		 ), updated_at = NOW() WHERE id = $1`, caseID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UnlinkAlertFromCase(ctx context.Context, caseID, alertID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM case_alerts WHERE case_id=$1 AND alert_id=$2`, caseID, alertID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE cases SET alert_count = (
		     SELECT COUNT(*) FROM case_alerts WHERE case_id = $1
		 ), updated_at = NOW() WHERE id = $1`, caseID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ── Case Notes ────────────────────────────────────────────────────────────────

func (s *Store) ListCaseNotes(ctx context.Context, caseID string) ([]models.CaseNote, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, case_id, body, author, created_at, updated_at
		 FROM case_notes WHERE case_id = $1 ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []models.CaseNote
	for rows.Next() {
		var n models.CaseNote
		if err := rows.Scan(&n.ID, &n.CaseID, &n.Body, &n.Author, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (s *Store) AddCaseNote(ctx context.Context, note *models.CaseNote) error {
	if note.ID == "" {
		note.ID = "note-" + uuid.New().String()
	}
	now := time.Now().UTC()
	note.CreatedAt = now
	note.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO case_notes (id, case_id, body, author, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		note.ID, note.CaseID, note.Body, note.Author, note.CreatedAt, note.UpdatedAt)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE cases SET updated_at = NOW() WHERE id = $1`, note.CaseID)
	return err
}

func (s *Store) UpdateCaseNote(ctx context.Context, id, body string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE case_notes SET body=$2, updated_at=NOW() WHERE id=$1`, id, body)
	return err
}

func (s *Store) DeleteCaseNote(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM case_notes WHERE id=$1`, id)
	return err
}
