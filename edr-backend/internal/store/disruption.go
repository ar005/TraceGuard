package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/youredr/edr-backend/internal/models"
)

// ── Disruption Policies ───────────────────────────────────────────────────────

func (s *Store) ListDisruptionPolicies(ctx context.Context, tenantID string) ([]models.DisruptionPolicy, error) {
	var out []models.DisruptionPolicy
	err := s.rdb().SelectContext(ctx, &out,
		`SELECT * FROM disruption_policies WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	return out, err
}

func (s *Store) ListEnabledDisruptionPolicies(ctx context.Context, tenantID string) ([]models.DisruptionPolicy, error) {
	var out []models.DisruptionPolicy
	err := s.rdb().SelectContext(ctx, &out,
		`SELECT * FROM disruption_policies WHERE tenant_id=$1 AND enabled=true ORDER BY min_severity DESC`, tenantID)
	return out, err
}

func (s *Store) GetDisruptionPolicy(ctx context.Context, id, tenantID string) (*models.DisruptionPolicy, error) {
	var p models.DisruptionPolicy
	err := s.rdb().GetContext(ctx, &p,
		`SELECT * FROM disruption_policies WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return &p, err
}

func (s *Store) CreateDisruptionPolicy(ctx context.Context, p *models.DisruptionPolicy) error {
	p.ID = "dp-" + uuid.New().String()
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	if p.RuleIDs == nil {
		p.RuleIDs = pq.StringArray{}
	}
	if p.HostGroups == nil {
		p.HostGroups = pq.StringArray{}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO disruption_policies
			(id, tenant_id, name, description, enabled, min_severity, rule_ids, host_groups, action, auto_release_hours, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		p.ID, p.TenantID, p.Name, p.Description, p.Enabled, p.MinSeverity,
		p.RuleIDs, p.HostGroups, p.Action, p.AutoReleaseHours, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *Store) UpdateDisruptionPolicy(ctx context.Context, p *models.DisruptionPolicy) error {
	p.UpdatedAt = time.Now()
	if p.RuleIDs == nil {
		p.RuleIDs = pq.StringArray{}
	}
	if p.HostGroups == nil {
		p.HostGroups = pq.StringArray{}
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE disruption_policies SET
			name=$3, description=$4, enabled=$5, min_severity=$6,
			rule_ids=$7, host_groups=$8, action=$9, auto_release_hours=$10, updated_at=$11
		WHERE id=$1 AND tenant_id=$2`,
		p.ID, p.TenantID, p.Name, p.Description, p.Enabled, p.MinSeverity,
		p.RuleIDs, p.HostGroups, p.Action, p.AutoReleaseHours, p.UpdatedAt)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func (s *Store) DeleteDisruptionPolicy(ctx context.Context, id, tenantID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM disruption_policies WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// ── Active Containments ───────────────────────────────────────────────────────

func (s *Store) InsertContainment(ctx context.Context, c *models.ActiveContainment) error {
	c.ID = "cnt-" + uuid.New().String()
	c.ContainedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO active_containments
			(id, tenant_id, policy_id, policy_name, alert_id, agent_id, hostname,
			 action, status, contained_at, release_at, released_by, release_note)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		c.ID, c.TenantID, c.PolicyID, c.PolicyName, c.AlertID, c.AgentID, c.Hostname,
		c.Action, c.Status, c.ContainedAt, c.ReleaseAt, c.ReleasedBy, c.ReleaseNote)
	return err
}

func (s *Store) ListContainments(ctx context.Context, tenantID, status string, limit, offset int) ([]models.ActiveContainment, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT * FROM active_containments WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	if status != "" {
		q += ` AND status=$2 ORDER BY contained_at DESC LIMIT $3 OFFSET $4`
		args = append(args, status, limit, offset)
	} else {
		q += ` ORDER BY contained_at DESC LIMIT $2 OFFSET $3`
		args = append(args, limit, offset)
	}
	var out []models.ActiveContainment
	err := s.rdb().SelectContext(ctx, &out, q, args...)
	return out, err
}

func (s *Store) GetContainment(ctx context.Context, id, tenantID string) (*models.ActiveContainment, error) {
	var c models.ActiveContainment
	err := s.rdb().GetContext(ctx, &c,
		`SELECT * FROM active_containments WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return &c, err
}

func (s *Store) ReleaseContainment(ctx context.Context, id, tenantID, releasedBy, note string) error {
	now := time.Now()
	res, err := s.db.ExecContext(ctx, `
		UPDATE active_containments
		SET status='released', released_at=$3, released_by=$4, release_note=$5
		WHERE id=$1 AND tenant_id=$2 AND status='active'`,
		id, tenantID, now, releasedBy, note)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("containment not found or already released")
	}
	return nil
}

func (s *Store) MarkContainmentFailed(ctx context.Context, id, detail string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE active_containments SET status='failed', release_note=$2 WHERE id=$1`, id, detail)
	return err
}

// ListExpiredContainments returns active containments whose release_at has passed.
func (s *Store) ListExpiredContainments(ctx context.Context) ([]models.ActiveContainment, error) {
	var out []models.ActiveContainment
	err := s.rdb().SelectContext(ctx, &out, `
		SELECT * FROM active_containments
		WHERE status='active' AND release_at IS NOT NULL AND release_at <= NOW()
		ORDER BY release_at ASC
		LIMIT 100`)
	return out, err
}

// IsAgentContained returns true if the agent already has an active containment.
func (s *Store) IsAgentContained(ctx context.Context, agentID string) (bool, error) {
	var count int
	err := s.rdb().GetContext(ctx, &count,
		`SELECT COUNT(*) FROM active_containments WHERE agent_id=$1 AND status='active'`, agentID)
	return count > 0, err
}
