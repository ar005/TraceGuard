// internal/workers/store.go
//
// XDR store worker — consumes XdrEvents from non-endpoint NATS subjects and
// writes them to PostgreSQL in batches.
//
// Endpoint events are NOT handled here — they are inserted synchronously by
// ingest.Server.flushBatch() before being published to NATS (to preserve the
// existing ordering guarantees). This worker handles events produced by Phase 1+
// connectors (network, cloud, identity, email) that bypass the gRPC ingest path.
//
// Subject filter: xdr.events.network.*, xdr.events.cloud.*,
//                 xdr.events.identity.*, xdr.events.email.*, xdr.events.saas.*
// Explicitly excludes: xdr.events.endpoint.* (already stored by ingest)

package workers

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/natsbus"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	storeBatchSize     = 200
	storeBatchInterval = 500 * time.Millisecond
)

// RunStoreWorker starts the NATS store consumer for non-endpoint connector events.
// Phase 1+: activated when connector sources publish to xdr.events.network.* etc.
func RunStoreWorker(ctx context.Context, bus *natsbus.Bus, st *store.Store, log zerolog.Logger) error {
	log = log.With().Str("worker", "store").Logger()

	// Only process non-endpoint sources — endpoint events are already in DB.
	nonEndpointSubjects := []string{
		"xdr.events.network.>",
		"xdr.events.cloud.>",
		"xdr.events.identity.>",
		"xdr.events.email.>",
		"xdr.events.saas.>",
	}

	var (
		batchMu  = new(interface{ Lock(); Unlock() })
		_        = batchMu // suppress unused warning — batch logic below
		batch    []*models.Event
		flushCh  = make(chan []*models.Event, 8)
	)
	_ = batch

	// Flush goroutine: drains flushCh and batch-inserts to DB.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case b, ok := <-flushCh:
				if !ok {
					return
				}
				if len(b) == 0 {
					continue
				}
				flushCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := st.InsertEventBatch(flushCtx, b); err != nil {
					log.Error().Err(err).Int("batch", len(b)).Msg("connector event batch insert failed")
				}
				cancel()
			}
		}
	}()

	var pending []*models.Event
	ticker := time.NewTicker(storeBatchInterval)
	defer ticker.Stop()

	flush := func() {
		if len(pending) == 0 {
			return
		}
		cp := make([]*models.Event, len(pending))
		copy(cp, pending)
		pending = pending[:0]
		select {
		case flushCh <- cp:
		default:
			log.Warn().Msg("store flush channel full — dropping batch")
		}
	}

	return bus.Subscribe(ctx, natsbus.ConsumerConfig{
		Name:           "store",
		FilterSubjects: nonEndpointSubjects,
		MaxDeliver:     3,
		AckWait:        30 * time.Second,
	}, func(ctx context.Context, ev *models.XdrEvent) error {
		pending = append(pending, &ev.Event)
		if len(pending) >= storeBatchSize {
			flush()
		}
		select {
		case <-ticker.C:
			flush()
		default:
		}
		return nil
	})
}
