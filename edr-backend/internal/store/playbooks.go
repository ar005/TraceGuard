// internal/store/playbooks.go — SOAR playbook + export destination store methods.

package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/youredr/edr-backend/internal/models"
)

// ── Playbooks ─────────────────────────────────────────────────────────────────

func (s *Store) ListPlaybooks(ctx context.Context) ([]models.Playbook, error) {
	var rows []models.Playbook
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, name, description, enabled, trigger_type, trigger_filter, actions,
		       run_count, last_run_at, created_at, updated_at, created_by
		FROM playbooks ORDER BY created_at DESC`)
	return rows, err
}

func (s *Store) GetPlaybook(ctx context.Context, id string) (*models.Playbook, error) {
	var p models.Playbook
	err := s.rdb().GetContext(ctx, &p, `
		SELECT id, name, description, enabled, trigger_type, trigger_filter, actions,
		       run_count, last_run_at, created_at, updated_at, created_by
		FROM playbooks WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) CreatePlaybook(ctx context.Context, p *models.Playbook) error {
	if p.ID == "" {
		p.ID = "pb-" + uuid.New().String()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO playbooks
		  (id, name, description, enabled, trigger_type, trigger_filter, actions, created_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		p.ID, p.Name, p.Description, p.Enabled, p.TriggerType,
		p.TriggerFilter, p.Actions, p.CreatedBy, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *Store) UpdatePlaybook(ctx context.Context, p *models.Playbook) error {
	p.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE playbooks SET
		  name = $2, description = $3, enabled = $4,
		  trigger_filter = $5, actions = $6, updated_at = $7
		WHERE id = $1`,
		p.ID, p.Name, p.Description, p.Enabled,
		p.TriggerFilter, p.Actions, p.UpdatedAt)
	return err
}

func (s *Store) DeletePlaybook(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM playbooks WHERE id = $1`, id)
	return err
}

func (s *Store) ListEnabledPlaybooks(ctx context.Context, triggerType string) ([]models.Playbook, error) {
	var rows []models.Playbook
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, name, description, enabled, trigger_type, trigger_filter, actions,
		       run_count, last_run_at, created_at, updated_at, created_by
		FROM playbooks WHERE enabled = TRUE AND trigger_type = $1`, triggerType)
	return rows, err
}

// ── Playbook Runs ─────────────────────────────────────────────────────────────

func (s *Store) InsertPlaybookRun(ctx context.Context, r *models.PlaybookRun) error {
	if r.ID == "" {
		r.ID = "run-" + uuid.New().String()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO playbook_runs
		  (id, playbook_id, playbook_name, trigger_type, trigger_id, status,
		   started_at, finished_at, actions_log, triggered_by, error)
		VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,$8,$9,$10)`,
		r.ID, r.PlaybookID, r.PlaybookName, r.TriggerType, r.TriggerID,
		r.Status, r.FinishedAt, r.ActionsLog, r.TriggeredBy, r.Error)
	return err
}

func (s *Store) UpdatePlaybookRun(ctx context.Context, id, status, errMsg string, actionsLog []byte) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE playbook_runs SET
		  status = $2, finished_at = $3, actions_log = $4, error = $5
		WHERE id = $1`, id, status, now, actionsLog, errMsg)
	return err
}

func (s *Store) ListPlaybookRuns(ctx context.Context, playbookID string, limit int) ([]models.PlaybookRun, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows []models.PlaybookRun
	var err error
	if playbookID != "" {
		err = s.rdb().SelectContext(ctx, &rows, `
			SELECT id, playbook_id, playbook_name, trigger_type, trigger_id, status,
			       started_at, finished_at, actions_log, triggered_by, error
			FROM playbook_runs WHERE playbook_id = $1
			ORDER BY started_at DESC LIMIT $2`, playbookID, limit)
	} else {
		err = s.rdb().SelectContext(ctx, &rows, `
			SELECT id, playbook_id, playbook_name, trigger_type, trigger_id, status,
			       started_at, finished_at, actions_log, triggered_by, error
			FROM playbook_runs
			ORDER BY started_at DESC LIMIT $1`, limit)
	}
	return rows, err
}

func (s *Store) IncrPlaybookRunCount(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE playbooks SET run_count = run_count + 1, last_run_at = NOW()
		WHERE id = $1`, id)
	return err
}

// ── Export Destinations ───────────────────────────────────────────────────────

func (s *Store) ListExportDestinations(ctx context.Context) ([]models.ExportDestination, error) {
	var rows []models.ExportDestination
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, name, dest_type, config, enabled, filter_sev, filter_types, created_at, updated_at
		FROM export_destinations ORDER BY created_at DESC`)
	return rows, err
}

func (s *Store) GetExportDestination(ctx context.Context, id string) (*models.ExportDestination, error) {
	var d models.ExportDestination
	err := s.rdb().GetContext(ctx, &d, `
		SELECT id, name, dest_type, config, enabled, filter_sev, filter_types, created_at, updated_at
		FROM export_destinations WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) UpsertExportDestination(ctx context.Context, d *models.ExportDestination) error {
	if d.ID == "" {
		d.ID = "exp-" + uuid.New().String()
	}
	now := time.Now()
	d.CreatedAt = now
	d.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO export_destinations
		  (id, name, dest_type, config, enabled, filter_sev, filter_types, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
		  name = EXCLUDED.name, dest_type = EXCLUDED.dest_type,
		  config = EXCLUDED.config, enabled = EXCLUDED.enabled,
		  filter_sev = EXCLUDED.filter_sev, filter_types = EXCLUDED.filter_types,
		  updated_at = NOW()`,
		d.ID, d.Name, d.DestType, d.Config, d.Enabled,
		d.FilterSev, d.FilterTypes, d.CreatedAt, d.UpdatedAt)
	return err
}

func (s *Store) DeleteExportDestination(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM export_destinations WHERE id = $1`, id)
	return err
}

func (s *Store) ListEnabledExportDestinations(ctx context.Context) ([]models.ExportDestination, error) {
	var rows []models.ExportDestination
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, name, dest_type, config, enabled, filter_sev, filter_types, created_at, updated_at
		FROM export_destinations WHERE enabled = TRUE`)
	return rows, err
}

// ─── Response Actions ─────────────────────────────────────────────────────────

// InsertResponseAction persists a response action record.
func (s *Store) InsertResponseAction(ctx context.Context, id, actionType, targetType, targetID, triggeredBy, playbookRunID string, params []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO response_actions
		    (id, action_type, target_type, target_id, status, triggered_by, playbook_run_id, params)
		VALUES ($1,$2,$3,$4,'active',$5,$6,$7)`,
		id, actionType, targetType, targetID, triggeredBy, playbookRunID, params)
	return err
}

// ListResponseActions returns recent response_actions rows.
func (s *Store) ListResponseActions(ctx context.Context, limit int) ([]models.ResponseAction, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows []models.ResponseAction
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, action_type, target_type, target_id, status, triggered_by,
		       playbook_run_id, params, result, created_at, reversed_at, reversed_by, notes
		FROM response_actions
		ORDER BY created_at DESC LIMIT $1`, limit)
	return rows, err
}
