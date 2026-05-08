// internal/store/containers.go — Container / Kubernetes inventory persistence.

package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/youredr/edr-backend/internal/models"
)

// ContainerInfo holds the container context extracted from an event payload.
type ContainerInfo struct {
	ContainerID string
	AgentID     string
	Hostname    string
	Runtime     string
	ImageName   string
	PodName     string
	Namespace   string
}

// ContainerRecord represents a tracked container instance.
type ContainerRecord struct {
	ContainerID string    `db:"container_id" json:"container_id"`
	AgentID     string    `db:"agent_id"     json:"agent_id"`
	Hostname    string    `db:"hostname"     json:"hostname"`
	Runtime     string    `db:"runtime"      json:"runtime"`
	ImageName   string    `db:"image_name"   json:"image_name"`
	PodName     string    `db:"pod_name"     json:"pod_name"`
	Namespace   string    `db:"namespace"    json:"namespace"`
	FirstSeen   time.Time `db:"first_seen"   json:"first_seen"`
	LastSeen    time.Time `db:"last_seen"    json:"last_seen"`
	EventCount  int64     `db:"event_count"  json:"event_count"`
}

// ContainerStats holds aggregate container inventory stats.
type ContainerStats struct {
	Total       int            `json:"total"`
	ByRuntime   map[string]int `json:"by_runtime"`
	ByNamespace map[string]int `json:"by_namespace"`
	Pods        int            `json:"pods"`
	Namespaces  int            `json:"namespaces"`
}

// ListContainersParams controls filtering for ListContainers.
type ListContainersParams struct {
	AgentID   string
	Runtime   string
	Namespace string
	Search    string
	Limit     int
	Offset    int
}

// UpsertContainer inserts or increments the event counter for a tracked container.
func (s *Store) UpsertContainer(ctx context.Context, info ContainerInfo) error {
	if info.ContainerID == "" || info.AgentID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO container_inventory
			(container_id, agent_id, hostname, runtime, image_name, pod_name, namespace, event_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
		ON CONFLICT (container_id, agent_id) DO UPDATE SET
			hostname    = EXCLUDED.hostname,
			runtime     = COALESCE(NULLIF(EXCLUDED.runtime,     ''), container_inventory.runtime),
			image_name  = COALESCE(NULLIF(EXCLUDED.image_name,  ''), container_inventory.image_name),
			pod_name    = COALESCE(NULLIF(EXCLUDED.pod_name,    ''), container_inventory.pod_name),
			namespace   = COALESCE(NULLIF(EXCLUDED.namespace,   ''), container_inventory.namespace),
			last_seen   = NOW(),
			event_count = container_inventory.event_count + 1
	`, info.ContainerID, info.AgentID, info.Hostname,
		info.Runtime, info.ImageName, info.PodName, info.Namespace)
	return err
}

// ListContainers returns a paginated list of container inventory records.
func (s *Store) ListContainers(ctx context.Context, p ListContainersParams) ([]ContainerRecord, int, error) {
	var whereParts []string
	var args []interface{}
	n := 1

	if p.AgentID != "" {
		whereParts = append(whereParts, fmt.Sprintf("agent_id = $%d", n))
		args = append(args, p.AgentID)
		n++
	}
	if p.Runtime != "" {
		whereParts = append(whereParts, fmt.Sprintf("runtime = $%d", n))
		args = append(args, p.Runtime)
		n++
	}
	if p.Namespace != "" {
		whereParts = append(whereParts, fmt.Sprintf("namespace = $%d", n))
		args = append(args, p.Namespace)
		n++
	}
	if p.Search != "" {
		whereParts = append(whereParts, fmt.Sprintf(
			"(container_id ILIKE $%d OR image_name ILIKE $%d OR pod_name ILIKE $%d OR hostname ILIKE $%d)",
			n, n+1, n+2, n+3))
		like := "%" + p.Search + "%"
		args = append(args, like, like, like, like)
		n += 4
	}

	where := ""
	if len(whereParts) > 0 {
		where = "WHERE " + strings.Join(whereParts, " AND ")
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	var total int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM container_inventory "+where,
		countArgs...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	if p.Limit <= 0 {
		p.Limit = 50
	}
	query := fmt.Sprintf(`
		SELECT container_id, agent_id, hostname, runtime, image_name, pod_name, namespace,
		       first_seen, last_seen, event_count
		FROM container_inventory
		%s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, where, n, n+1)
	args = append(args, p.Limit, p.Offset)

	rows, err := s.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var records []ContainerRecord
	for rows.Next() {
		var r ContainerRecord
		if err := rows.StructScan(&r); err != nil {
			return nil, 0, err
		}
		records = append(records, r)
	}
	if records == nil {
		records = []ContainerRecord{}
	}
	return records, total, rows.Err()
}

// GetContainerRecord returns a single container by its compound key.
func (s *Store) GetContainerRecord(ctx context.Context, containerID, agentID string) (*ContainerRecord, error) {
	var r ContainerRecord
	err := s.db.QueryRowxContext(ctx, `
		SELECT container_id, agent_id, hostname, runtime, image_name, pod_name, namespace,
		       first_seen, last_seen, event_count
		FROM container_inventory
		WHERE container_id = $1 AND agent_id = $2
	`, containerID, agentID).StructScan(&r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetContainerStats returns aggregate container inventory stats.
func (s *Store) GetContainerStats(ctx context.Context) (*ContainerStats, error) {
	stats := &ContainerStats{
		ByRuntime:   map[string]int{},
		ByNamespace: map[string]int{},
	}

	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM container_inventory",
	).Scan(&stats.Total); err != nil {
		return nil, err
	}

	runtimeRows, err := s.db.QueryxContext(ctx,
		`SELECT runtime, COUNT(*) as cnt FROM container_inventory
		 WHERE runtime != '' GROUP BY runtime ORDER BY cnt DESC`)
	if err != nil {
		return nil, err
	}
	defer runtimeRows.Close()
	for runtimeRows.Next() {
		var rt string
		var cnt int
		if err := runtimeRows.Scan(&rt, &cnt); err != nil {
			return nil, err
		}
		stats.ByRuntime[rt] = cnt
	}
	runtimeRows.Close()

	nsRows, err := s.db.QueryxContext(ctx,
		`SELECT namespace, COUNT(*) as cnt FROM container_inventory
		 WHERE namespace != '' GROUP BY namespace ORDER BY cnt DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer nsRows.Close()
	for nsRows.Next() {
		var ns string
		var cnt int
		if err := nsRows.Scan(&ns, &cnt); err != nil {
			return nil, err
		}
		stats.ByNamespace[ns] = cnt
		stats.Namespaces++
	}
	nsRows.Close()

	s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT pod_name) FROM container_inventory WHERE pod_name != ''`,
	).Scan(&stats.Pods)

	return stats, nil
}

// GetContainerEvents returns paginated events for a specific container.
// Uses the GIN index on payload via the @> containment operator.
func (s *Store) GetContainerEvents(ctx context.Context, containerID string, limit, offset int) ([]*models.Event, int, error) {
	if limit <= 0 {
		limit = 50
	}
	// Build a JSONB containment literal. Container IDs are UUIDs / hex strings —
	// no special chars, but escape the one quote just in case.
	safeID := strings.ReplaceAll(containerID, "'", "''")
	containsJSON := fmt.Sprintf(`{"process":{"container_id":"%s"}}`, safeID)

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE payload @> $1::jsonb`,
		containsJSON,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryxContext(ctx, `
		SELECT id, agent_id, hostname, event_type, timestamp, payload,
		       received_at, severity, rule_id, alert_id
		FROM events
		WHERE payload @> $1::jsonb
		ORDER BY timestamp DESC
		LIMIT $2 OFFSET $3
	`, containsJSON, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.Event
	for rows.Next() {
		var e models.Event
		if err := rows.StructScan(&e); err != nil {
			return nil, 0, err
		}
		events = append(events, &e)
	}
	if events == nil {
		events = []*models.Event{}
	}
	return events, total, rows.Err()
}
