// internal/workers/risk_decay.go
//
// RiskDecayWorker runs every 24 hours and reduces every identity's risk_score
// by 10 points (floor 0). This prevents stale high-risk labels from persisting
// indefinitely after a user's behaviour normalises.

package workers

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// RiskDecayStore is the DB interface required by RiskDecayWorker.
type RiskDecayStore interface {
	DecayAllRiskScores(ctx context.Context, decayAmount int16) (int64, error)
}

// RiskDecayWorker periodically decays identity risk scores.
type RiskDecayWorker struct {
	store    RiskDecayStore
	interval time.Duration
	decay    int16
	log      zerolog.Logger
}

// NewRiskDecayWorker creates a worker that decays scores by decayAmount every interval.
func NewRiskDecayWorker(st RiskDecayStore, interval time.Duration, decayAmount int16, log zerolog.Logger) *RiskDecayWorker {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if decayAmount <= 0 {
		decayAmount = 10
	}
	return &RiskDecayWorker{
		store:    st,
		interval: interval,
		decay:    decayAmount,
		log:      log.With().Str("worker", "risk-decay").Logger(),
	}
}

// Run starts the decay loop. Blocks until ctx is cancelled.
func (w *RiskDecayWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := w.store.DecayAllRiskScores(ctx, w.decay)
			if err != nil {
				w.log.Warn().Err(err).Msg("risk score decay failed")
			} else {
				w.log.Debug().Int64("rows", n).Int16("decay", w.decay).Msg("risk scores decayed")
			}
		}
	}
}
