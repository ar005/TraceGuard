// Package surface computes and caches per-agent attack surface snapshots.
package surface

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Store is the subset of store.Store needed by the scanner.
type Store interface {
	ListAgents(ctx context.Context) ([]models.Agent, error)
	ComputeAgentAttackSurface(ctx context.Context, agentID string) ([]store.OpenPort, []store.ExposedVuln, error)
	UpsertAttackSurfaceSnapshot(ctx context.Context, snap *store.AttackSurfaceSnapshot) error
}

// Scanner runs every 15 minutes and writes attack surface snapshots.
type Scanner struct {
	store Store
	log   zerolog.Logger
}

// New creates a Scanner.
func New(st Store, log zerolog.Logger) *Scanner {
	return &Scanner{store: st, log: log.With().Str("component", "attack-surface-scanner").Logger()}
}

// Run starts the scan loop. Blocks until ctx is cancelled.
func (sc *Scanner) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	go sc.scan(ctx) // first scan shortly after startup

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.scan(ctx)
		}
	}
}

func (sc *Scanner) scan(ctx context.Context) {
	agents, err := sc.store.ListAgents(ctx)
	if err != nil {
		sc.log.Warn().Err(err).Msg("list agents for surface scan")
		return
	}

	sevScore := map[string]int16{"CRITICAL": 80, "HIGH": 60, "MEDIUM": 40, "LOW": 20, "UNKNOWN": 10}
	scanned := 0

	for _, a := range agents {
		if !a.IsOnline {
			continue // only scan live agents
		}
		ports, vulns, err := sc.store.ComputeAgentAttackSurface(ctx, a.ID)
		if err != nil {
			sc.log.Warn().Err(err).Str("agent", a.ID).Msg("compute attack surface")
			continue
		}

		// Derive a surface risk score from the worst exposed vuln.
		var surfaceScore int16
		for _, v := range vulns {
			if s, ok := sevScore[v.Severity]; ok && s > surfaceScore {
				surfaceScore = s
			}
		}

		portsJSON, _ := json.Marshal(ports)
		vulnsJSON, _ := json.Marshal(vulns)

		snap := &store.AttackSurfaceSnapshot{
			ID:           "as-" + uuid.New().String(),
			TenantID:     "default",
			AgentID:      a.ID,
			OpenPorts:    json.RawMessage(portsJSON),
			ExposedVulns: json.RawMessage(vulnsJSON),
			RiskScore:    surfaceScore,
		}
		if err := sc.store.UpsertAttackSurfaceSnapshot(ctx, snap); err != nil {
			sc.log.Warn().Err(err).Str("agent", a.ID).Msg("upsert attack surface snapshot")
		}
		scanned++
	}
	sc.log.Info().Int("agents_scanned", scanned).Msg("attack surface scan complete")
}
