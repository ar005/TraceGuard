// internal/workers/detection.go
//
// XDR detection worker — consumes XdrEvents from the NATS XDR_EVENTS stream
// and drives the detection engine asynchronously.
//
// This replaces the synchronous engine.Evaluate() call inside ingest.flushBatch
// when NATS is enabled, decoupling detection throughput from ingest throughput.
//
// Multiple detection workers can run in parallel (NATS queue group "detection")
// to horizontally scale detection capacity independent of ingest capacity.

package workers

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/natsbus"
)

// RunDetectionWorker starts the NATS detection consumer.
// It processes all xdr.events.> subjects and calls engine.EvaluateXdr per event.
// Returns when ctx is cancelled; non-nil error indicates startup failure.
func RunDetectionWorker(ctx context.Context, bus *natsbus.Bus, eng *detection.Engine, log zerolog.Logger) error {
	log = log.With().Str("worker", "detection").Logger()

	return bus.Subscribe(ctx, natsbus.ConsumerConfig{
		Name:       "detection",
		MaxDeliver: 3,
		AckWait:    30 * time.Second,
	}, func(ctx context.Context, ev *models.XdrEvent) error {
		start := time.Now()
		eng.EvaluateXdr(ctx, ev)
		metrics.DetectionDuration.Observe(time.Since(start).Seconds())
		return nil
	})
}
