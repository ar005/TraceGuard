// Package riskhist records hourly risk-score snapshots for trend analysis.
package riskhist

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// Store is the subset of store.Store needed by the recorder.
type Store interface {
	ListAllRiskableAgents(ctx context.Context) ([]models.Agent, error)
	ListAllRiskableIdentities(ctx context.Context) ([]models.IdentityRecord, error)
	RecordRiskScoreSnapshot(ctx context.Context, tenantID, entityType, entityID string, score int16, factors json.RawMessage) error
}

// Recorder takes hourly snapshots of all agent and user risk scores.
type Recorder struct {
	store Store
	log   zerolog.Logger
}

// New creates a Recorder.
func New(store Store, log zerolog.Logger) *Recorder {
	return &Recorder{
		store: store,
		log:   log.With().Str("component", "risk-hist-recorder").Logger(),
	}
}

// Run starts the hourly snapshot loop. Blocks until ctx is cancelled.
func (r *Recorder) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// First snapshot shortly after startup (avoid blocking start).
	go r.snapshot(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.snapshot(ctx)
		}
	}
}

func (r *Recorder) snapshot(ctx context.Context) {
	agents, err := r.store.ListAllRiskableAgents(ctx)
	if err != nil {
		r.log.Warn().Err(err).Msg("list riskable agents")
	} else {
		for _, a := range agents {
			factors := json.RawMessage(a.RiskFactors)
			if len(factors) == 0 {
				factors = json.RawMessage(`[]`)
			}
			if err := r.store.RecordRiskScoreSnapshot(ctx, "default", "agent", a.ID, a.RiskScore, factors); err != nil {
				r.log.Warn().Err(err).Str("agent", a.ID).Msg("record agent snapshot")
			}
		}
	}

	identities, err := r.store.ListAllRiskableIdentities(ctx)
	if err != nil {
		r.log.Warn().Err(err).Msg("list riskable identities")
	} else {
		for _, u := range identities {
			factors := json.RawMessage(u.RiskFactors)
			if len(factors) == 0 {
				factors = json.RawMessage(`[]`)
			}
			if err := r.store.RecordRiskScoreSnapshot(ctx, "default", "user", u.CanonicalUID, u.RiskScore, factors); err != nil {
				r.log.Warn().Err(err).Str("uid", u.CanonicalUID).Msg("record user snapshot")
			}
		}
	}

	r.log.Info().Int("agents", len(agents)).Int("users", len(identities)).Msg("risk history snapshot complete")
}
