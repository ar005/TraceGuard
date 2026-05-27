// internal/store/agent_groups.go
// CRUD for agent_groups and group membership resolution.

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/youredr/edr-backend/internal/models"
)

// ListAgentGroups returns all groups for a tenant ordered by name.
func (s *Store) ListAgentGroups(ctx context.Context, tenantID string) ([]models.AgentGroup, error) {
	var rows []models.AgentGroup
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, tenant_id, name, description, color, tag_filter, env_filter, created_at, updated_at
		FROM agent_groups
		WHERE tenant_id = $1
		ORDER BY name`, tenantID)
	return rows, err
}

// GetAgentGroup returns one group by ID within a tenant.
func (s *Store) GetAgentGroup(ctx context.Context, id, tenantID string) (*models.AgentGroup, error) {
	var g models.AgentGroup
	err := s.rdb().GetContext(ctx, &g, `
		SELECT id, tenant_id, name, description, color, tag_filter, env_filter, created_at, updated_at
		FROM agent_groups
		WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// CreateAgentGroup inserts a new agent group and returns it.
func (s *Store) CreateAgentGroup(ctx context.Context, g *models.AgentGroup) (*models.AgentGroup, error) {
	if g.ID == "" {
		g.ID = "grp-" + uuid.New().String()
	}
	now := time.Now()
	g.CreatedAt = now
	g.UpdatedAt = now
	if g.Color == "" {
		g.Color = "#6366f1"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_groups (id, tenant_id, name, description, color, tag_filter, env_filter, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.ID, g.TenantID, g.Name, g.Description, g.Color,
		pq.Array(coalesceStringSlice(g.TagFilter)), g.EnvFilter,
		g.CreatedAt, g.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create agent group: %w", err)
	}
	return g, nil
}

// UpdateAgentGroup replaces mutable fields on an agent group.
func (s *Store) UpdateAgentGroup(ctx context.Context, g *models.AgentGroup) error {
	g.UpdatedAt = time.Now()
	res, err := s.db.ExecContext(ctx, `
		UPDATE agent_groups
		SET name=$1, description=$2, color=$3, tag_filter=$4, env_filter=$5, updated_at=$6
		WHERE id=$7 AND tenant_id=$8`,
		g.Name, g.Description, g.Color,
		pq.Array(coalesceStringSlice(g.TagFilter)), g.EnvFilter,
		g.UpdatedAt, g.ID, g.TenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent group not found")
	}
	return nil
}

// DeleteAgentGroup removes a group by ID within a tenant.
func (s *Store) DeleteAgentGroup(ctx context.Context, id, tenantID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM agent_groups WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// AgentBelongsToGroup returns true when the agent satisfies the group's membership filter.
// TagFilter is all-of: every tag in the filter must be present on the agent.
// EnvFilter is exact match when non-empty.
func AgentBelongsToGroup(agent *models.Agent, group *models.AgentGroup) bool {
	if len(group.TagFilter) > 0 {
		tagSet := make(map[string]struct{}, len(agent.Tags))
		for _, t := range agent.Tags {
			tagSet[t] = struct{}{}
		}
		for _, required := range group.TagFilter {
			if _, ok := tagSet[required]; !ok {
				return false
			}
		}
	}
	if group.EnvFilter != "" && agent.Env != group.EnvFilter {
		return false
	}
	return true
}

// ListGroupsForAgent returns all group IDs the agent belongs to within a tenant.
func (s *Store) ListGroupsForAgent(ctx context.Context, agentID, tenantID string) ([]string, error) {
	agent, err := s.GetAgent(ctx, agentID, "default")
	if err != nil {
		return nil, err
	}
	groups, err := s.ListAgentGroups(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, g := range groups {
		if AgentBelongsToGroup(agent, &g) {
			ids = append(ids, g.ID)
		}
	}
	return ids, nil
}

// ListAgentGroupMembers returns all agents that belong to a specific group.
func (s *Store) ListAgentGroupMembers(ctx context.Context, groupID, tenantID string) ([]models.Agent, error) {
	group, err := s.GetAgentGroup(ctx, groupID, tenantID)
	if err != nil {
		return nil, err
	}

	var agents []models.Agent
	err = s.rdb().SelectContext(ctx, &agents, `
		SELECT id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen,
		       is_online, config_ver, tags, env, notes, risk_score, risk_updated_at
		FROM agents
		ORDER BY hostname`)
	if err != nil {
		return nil, err
	}

	var members []models.Agent
	for _, a := range agents {
		if AgentBelongsToGroup(&a, group) {
			members = append(members, a)
		}
	}
	return members, nil
}
