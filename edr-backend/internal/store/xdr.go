// internal/store/xdr.go
// XDR source CRUD — xdr_sources table operations.

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/youredr/edr-backend/internal/models"
)

// ListSources returns all xdr_sources rows ordered by name.
func (s *Store) ListSources(ctx context.Context) ([]models.XdrSource, error) {
	var rows []models.XdrSource
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, name, source_type, connector, config, enabled,
		       last_seen_at, events_today, error_state, created_at, updated_at
		FROM xdr_sources
		ORDER BY name`)
	return rows, err
}

// GetSource returns one xdr_sources row by ID.
func (s *Store) GetSource(ctx context.Context, id string) (*models.XdrSource, error) {
	var row models.XdrSource
	err := s.rdb().GetContext(ctx, &row, `
		SELECT id, name, source_type, connector, config, enabled,
		       last_seen_at, events_today, error_state, created_at, updated_at
		FROM xdr_sources WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// CreateSource inserts a new xdr_sources row and returns it.
func (s *Store) CreateSource(ctx context.Context, in *models.XdrSource) (*models.XdrSource, error) {
	if in.ID == "" {
		in.ID = uuid.New().String()
	}
	now := time.Now()
	in.CreatedAt = now
	in.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO xdr_sources (id, name, source_type, connector, config, enabled,
		                         error_state, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		in.ID, in.Name, in.SourceType, in.Connector, in.Config,
		in.Enabled, in.ErrorState, in.CreatedAt, in.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}
	return in, nil
}

// UpdateSource replaces mutable fields on an xdr_sources row.
func (s *Store) UpdateSource(ctx context.Context, in *models.XdrSource) error {
	in.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE xdr_sources
		SET name=$1, source_type=$2, connector=$3, config=$4,
		    enabled=$5, updated_at=$6
		WHERE id=$7`,
		in.Name, in.SourceType, in.Connector, in.Config,
		in.Enabled, in.UpdatedAt, in.ID)
	return err
}

// DeleteSource removes an xdr_sources row.
func (s *Store) DeleteSource(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM xdr_sources WHERE id = $1`, id)
	return err
}

// TouchSource updates last_seen_at and increments events_today.
func (s *Store) TouchSource(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE xdr_sources
		SET last_seen_at = NOW(), events_today = events_today + 1, error_state = ''
		WHERE id = $1`, id)
	return err
}

// SetSourceError records a connector error string; clears it when msg is empty.
func (s *Store) SetSourceError(ctx context.Context, id string, msg string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE xdr_sources SET error_state = $1, updated_at = NOW()
		WHERE id = $2`, msg, id)
	return err
}

// ListXdrEvents returns events from non-endpoint sources, with optional filtering.
func (s *Store) ListXdrEvents(ctx context.Context, sourceType, sourceID, eventType string, limit, offset int) ([]models.XdrEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	args := []interface{}{}
	where := "WHERE source_type != 'endpoint'"
	n := 1

	if sourceType != "" {
		where += fmt.Sprintf(" AND source_type = $%d", n)
		args = append(args, sourceType)
		n++
	}
	if sourceID != "" {
		where += fmt.Sprintf(" AND source_id = $%d", n)
		args = append(args, sourceID)
		n++
	}
	if eventType != "" {
		where += fmt.Sprintf(" AND event_type = $%d", n)
		args = append(args, eventType)
		n++
	}
	args = append(args, limit, offset)

	var rows []models.XdrEvent
	err := s.rdb().SelectContext(ctx, &rows, fmt.Sprintf(`
		SELECT id, agent_id, hostname, event_type, timestamp, payload, received_at, severity,
		       rule_id, alert_id, class_uid, category_uid, source_type, source_id, tenant_id,
		       user_uid, raw_log, enrichments
		FROM events
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	return rows, err
}

// GetIdentityByUID looks up an identity_graph row by canonical_uid.
func (s *Store) GetIdentityByUID(ctx context.Context, uid string) (*models.IdentityRecord, error) {
	var rec models.IdentityRecord
	err := s.rdb().GetContext(ctx, &rec, `
		SELECT id, canonical_uid, display_name, email, department,
		       account_ids, aliases, risk_score, risk_factors, is_privileged,
		       agent_ids, last_login_at, last_seen_src, updated_at
		FROM identity_graph WHERE canonical_uid = $1`, uid)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}
