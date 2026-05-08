// internal/natsbus/bus.go
//
// NATS JetStream bus — the backbone of the XDR pipeline.
//
// Architecture:
//   Connectors/ingest → Publish() → NATS stream "XDR_EVENTS"
//   detection-worker  → Subscribe() → Engine.Evaluate()
//   store-worker      → Subscribe() → store.InsertXdrEvent() (Phase 1+)
//
// Subject convention: xdr.events.<source_type>.<source_id>
// Examples:
//   xdr.events.endpoint.agent-abc123
//   xdr.events.network.zeek-prod
//   xdr.events.cloud.cloudtrail-aws-prod
//   xdr.events.identity.okta-corp
//
// When NATS is disabled (cfg.NATS.Enabled = false), the Bus methods are
// no-ops and detection continues synchronously in the ingest path.

package natsbus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

const (
	StreamName      = "XDR_EVENTS"
	streamSubject   = "xdr.events.>"
	MaxMsgSize      = 1 << 20 // 1 MB per event
	StreamMaxAge    = 24 * time.Hour
)

// Bus wraps a NATS JetStream connection for the XDR event pipeline.
type Bus struct {
	nc  *nats.Conn
	js  jetstream.JetStream
	log zerolog.Logger
}

// New connects to NATS and returns a ready Bus.
// Call EnsureStream before Publish or Subscribe.
func New(url string, log zerolog.Logger) (*Bus, error) {
	nc, err := nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info().Msg("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect %s: %w", url, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	return &Bus{
		nc:  nc,
		js:  js,
		log: log.With().Str("component", "natsbus").Logger(),
	}, nil
}

// EnsureStream creates or updates the XDR_EVENTS JetStream stream.
// Safe to call on every startup — idempotent.
func (b *Bus) EnsureStream(ctx context.Context) error {
	_, err := b.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        StreamName,
		Subjects:    []string{streamSubject},
		Retention:   jetstream.WorkQueuePolicy,
		MaxAge:      StreamMaxAge,
		Storage:     jetstream.FileStorage,
		MaxMsgSize:  MaxMsgSize,
		Replicas:    1,
		Description: "XDR unified event pipeline",
	})
	if err != nil {
		return fmt.Errorf("ensure stream: %w", err)
	}
	b.log.Info().Str("stream", StreamName).Msg("JetStream stream ready")
	return nil
}

// Publish serialises ev and publishes it to the appropriate subject.
// Non-blocking: uses a 2-second context deadline to avoid stalling hot paths.
func (b *Bus) Publish(ev *models.XdrEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal xdr event: %w", err)
	}
	subject := fmt.Sprintf("xdr.events.%s.%s", ev.SourceType, ev.SourceID)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}
	return nil
}

// ConsumerConfig holds parameters for creating a durable consumer.
type ConsumerConfig struct {
	// Name is the durable consumer name (e.g. "detection", "store").
	Name string
	// FilterSubjects restricts which subjects this consumer receives.
	// Empty = all xdr.events.> subjects.
	FilterSubjects []string
	// MaxDeliver is how many times a message is re-delivered before being dropped.
	MaxDeliver int
	// AckWait is the time NATS waits for an ack before redelivery.
	AckWait time.Duration
}

// Subscribe creates (or resumes) a durable pull consumer and returns a
// channel of decoded XdrEvents. The goroutine exits when ctx is cancelled.
// handler is called for each message; returning nil acks, non-nil naks.
func (b *Bus) Subscribe(ctx context.Context, cfg ConsumerConfig, handler func(ctx context.Context, ev *models.XdrEvent) error) error {
	maxDeliver := cfg.MaxDeliver
	if maxDeliver <= 0 {
		maxDeliver = 3
	}
	ackWait := cfg.AckWait
	if ackWait <= 0 {
		ackWait = 30 * time.Second
	}

	ccfg := jetstream.ConsumerConfig{
		Durable:    cfg.Name,
		AckPolicy:  jetstream.AckExplicitPolicy,
		MaxDeliver: maxDeliver,
		AckWait:    ackWait,
	}
	if len(cfg.FilterSubjects) > 0 {
		ccfg.FilterSubjects = cfg.FilterSubjects
	}

	cons, err := b.js.CreateOrUpdateConsumer(ctx, StreamName, ccfg)
	if err != nil {
		return fmt.Errorf("create consumer %q: %w", cfg.Name, err)
	}

	iter, err := cons.Messages()
	if err != nil {
		return fmt.Errorf("consumer messages iter: %w", err)
	}

	go func() {
		defer iter.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			msg, err := iter.Next()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				b.log.Warn().Err(err).Str("consumer", cfg.Name).Msg("NATS iter error")
				time.Sleep(500 * time.Millisecond)
				continue
			}

			var ev models.XdrEvent
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				b.log.Warn().Err(err).Str("consumer", cfg.Name).Msg("failed to decode XdrEvent — discarding")
				_ = msg.Ack()
				continue
			}

			if err := handler(ctx, &ev); err != nil {
				b.log.Warn().Err(err).Str("consumer", cfg.Name).Str("event", ev.ID).Msg("handler error — naking")
				_ = msg.Nak()
			} else {
				_ = msg.Ack()
			}
		}
	}()

	b.log.Info().Str("consumer", cfg.Name).Msg("NATS consumer started")
	return nil
}

// NATSSink adapts Bus.Publish to the ingest.EventSink interface.
// Use this when wiring the bus into the ingest server.
type NATSSink struct{ bus *Bus }

// NewSink wraps a Bus as an EventSink for ingest.Server.
func NewSink(bus *Bus) *NATSSink { return &NATSSink{bus: bus} }

// Publish implements ingest.EventSink.
func (s *NATSSink) Publish(ev *models.XdrEvent) error { return s.bus.Publish(ev) }

// JS returns the underlying JetStream context for advanced use.
func (b *Bus) JS() jetstream.JetStream { return b.js }

// Close drains the NATS connection gracefully.
func (b *Bus) Close() {
	if b.nc != nil {
		_ = b.nc.Drain()
	}
}
