// Package ioclifecycle runs daily IOC maintenance: expiry and confidence decay.
package ioclifecycle

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/store"
)

// Decayer runs nightly IOC lifecycle maintenance.
type Decayer struct {
	st  *store.Store
	log zerolog.Logger
}

func New(st *store.Store, log zerolog.Logger) *Decayer {
	return &Decayer{st: st, log: log.With().Str("component", "ioc-decayer").Logger()}
}

// Run blocks until ctx is cancelled, firing decay logic once at startup and
// then every 24 hours.
func (d *Decayer) Run(ctx context.Context) {
	d.decay(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.decay(ctx)
		}
	}
}

func (d *Decayer) decay(ctx context.Context) {
	expired, decayed, err := d.st.DecayStaleIOCs(ctx)
	if err != nil {
		d.log.Error().Err(err).Msg("IOC decay run failed")
	} else if expired > 0 || decayed > 0 {
		d.log.Info().
			Int64("expired", expired).
			Int64("confidence_decayed", decayed).
			Msg("IOC lifecycle maintenance complete")
	}

	if err := d.st.RefreshFeedQualityScores(ctx); err != nil {
		d.log.Error().Err(err).Msg("feed quality refresh failed")
	}

	disabled, err := d.st.AutoDisableStaleFeeds(ctx)
	if err != nil {
		d.log.Error().Err(err).Msg("auto-disable stale feeds failed")
	} else if disabled > 0 {
		d.log.Info().Int64("disabled", disabled).Msg("auto-disabled stale TAXII feeds")
	}
}
