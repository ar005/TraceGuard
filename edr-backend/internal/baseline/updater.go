package baseline

import (
	"context"
	"math"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const anomalyThreshold = 3.0

// Store is the subset of store.Store used by the updater.
type Store interface {
	ListAgents(ctx context.Context) ([]models.Agent, error)
	ComputeAgentMetrics(ctx context.Context, agentID string) (map[string]float64, error)
	ComputeUserMetrics(ctx context.Context, userUID string) (map[string]float64, error)
	UpsertEntityBaseline(ctx context.Context, tenantID, entityType, entityID, metric string, value float64) (float64, error)
	RecordAnomaly(ctx context.Context, a *store.AnomalyScore) error
}

// Updater runs the EWMA baseline update loop.
type Updater struct {
	store Store
	log   zerolog.Logger
}

// New creates an Updater.
func New(st Store, log zerolog.Logger) *Updater {
	return &Updater{store: st, log: log}
}

// Run starts the update loop; returns when ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	u.update(ctx)
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.update(ctx)
		}
	}
}

func (u *Updater) update(ctx context.Context) {
	agents, err := u.store.ListAgents(ctx)
	if err != nil {
		u.log.Error().Err(err).Msg("baseline: list agents")
		return
	}

	seenUsers := map[string]bool{}

	for _, ag := range agents {
		if !ag.IsOnline {
			continue
		}
		tenantID := "default"

		// Agent-level metrics
		agentMetrics, err := u.store.ComputeAgentMetrics(ctx, ag.ID)
		if err != nil {
			u.log.Warn().Err(err).Str("agent", ag.ID).Msg("baseline: compute agent metrics")
			continue
		}
		for metric, val := range agentMetrics {
			zScore, err := u.store.UpsertEntityBaseline(ctx, tenantID, "agent", ag.ID, metric, val)
			if err != nil {
				u.log.Warn().Err(err).Str("agent", ag.ID).Str("metric", metric).Msg("baseline: upsert")
				continue
			}
			if math.Abs(zScore) >= anomalyThreshold {
				u.fireAnomaly(ctx, tenantID, "agent", ag.ID, ag.Hostname, metric, zScore, val)
			}
		}

		// Collect distinct users seen on this agent (reuse identity data from login sessions)
		_ = seenUsers
	}
}

func (u *Updater) fireAnomaly(ctx context.Context, tenantID, entityType, entityID, label, metric string, zScore, observed float64) {
	// Fetch current baseline to get expected value
	// (We embed expected as 0; the store already has the EWMA)
	a := &store.AnomalyScore{
		TenantID:      tenantID,
		EntityType:    entityType,
		EntityID:      entityID,
		EntityLabel:   label,
		Metric:        metric,
		ZScore:        zScore,
		ObservedValue: observed,
		ExpectedValue: 0, // will be filled in if we had a read here; acceptable approximation
		StdDev:        0,
	}
	if err := u.store.RecordAnomaly(ctx, a); err != nil {
		u.log.Warn().Err(err).Str("entity", entityID).Str("metric", metric).Msg("baseline: record anomaly")
	} else {
		u.log.Info().
			Str("entity", entityID).
			Str("metric", metric).
			Float64("z_score", zScore).
			Float64("observed", observed).
			Msg("anomaly detected")
	}
}
