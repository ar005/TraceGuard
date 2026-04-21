// internal/connectors/connector.go
//
// XDR Connector Framework — Phase 1
//
// A Connector is any source adapter that ingests events from a non-endpoint
// source (network, cloud, identity, email, SaaS) and publishes normalized
// XdrEvents to the NATS pipeline via EventSink.
//
// Registry manages connector lifecycle (start, stop, health-check, reload).
// Connectors are instantiated from xdr_sources DB rows at startup and when
// new sources are added via POST /api/v1/sources.

package connectors

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// EventSink is the publication target for normalized XdrEvents.
// natsbus.NATSSink implements this interface — connectors never import natsbus directly.
type EventSink interface {
	Publish(ev *models.XdrEvent) error
}

// Connector is the single interface every source adapter must implement.
type Connector interface {
	// ID returns the connector instance ID (matches xdr_sources.id).
	ID() string

	// SourceType returns the OCSF-aligned source category.
	SourceType() string // network|cloud|identity|email|saas

	// Start consumes from the source, calling sink.Publish for each event.
	// Must return promptly (≤5s) when ctx is cancelled.
	Start(ctx context.Context, sink EventSink) error

	// Health returns a non-nil error if the connector cannot reach its source.
	Health(ctx context.Context) error
}

// Factory builds a Connector from an XdrSource DB record.
// Each connector type registers a Factory in the global FactoryRegistry.
type Factory func(src *models.XdrSource, log zerolog.Logger) (Connector, error)

var (
	factoryMu sync.RWMutex
	factories = map[string]Factory{} // connector type → factory
)

// RegisterFactory registers a Factory for a connector type name.
// Called from connector package init() functions.
func RegisterFactory(connectorType string, f Factory) {
	factoryMu.Lock()
	factories[connectorType] = f
	factoryMu.Unlock()
}

// Build creates a Connector from an XdrSource using the registered factory.
func Build(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
	factoryMu.RLock()
	f, ok := factories[src.Connector]
	factoryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown connector type %q — register a Factory first", src.Connector)
	}
	return f(src, log)
}

// Registry manages active connector goroutines.
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]Connector
	cancels    map[string]context.CancelFunc
	sink       EventSink
	store      *store.Store
	log        zerolog.Logger
}

// NewRegistry creates a Registry backed by the given EventSink.
func NewRegistry(sink EventSink, st *store.Store, log zerolog.Logger) *Registry {
	return &Registry{
		connectors: make(map[string]Connector),
		cancels:    make(map[string]context.CancelFunc),
		sink:       sink,
		store:      st,
		log:        log.With().Str("component", "connector-registry").Logger(),
	}
}

// Register adds a connector to the registry without starting it.
func (r *Registry) Register(c Connector) {
	r.mu.Lock()
	r.connectors[c.ID()] = c
	r.mu.Unlock()
}

// Start launches a connector in a goroutine. Idempotent: re-starting an already
// running connector first stops the previous instance.
func (r *Registry) Start(ctx context.Context, id string) error {
	r.mu.Lock()
	c, ok := r.connectors[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("connector %q not registered", id)
	}
	// Stop any existing instance.
	if cancel, running := r.cancels[id]; running {
		cancel()
	}
	cctx, cancel := context.WithCancel(ctx)
	r.cancels[id] = cancel
	r.mu.Unlock()

	go func() {
		r.log.Info().Str("id", id).Str("type", c.SourceType()).Msg("connector starting")
		if err := c.Start(cctx, r.sink); err != nil && !errors.Is(err, context.Canceled) {
			r.log.Error().Err(err).Str("id", id).Msg("connector exited with error")
			_ = r.store.SetSourceError(context.Background(), id, err.Error())
		}
		r.log.Info().Str("id", id).Msg("connector stopped")
	}()
	return nil
}

// Stop cancels a running connector.
func (r *Registry) Stop(id string) {
	r.mu.Lock()
	if cancel, ok := r.cancels[id]; ok {
		cancel()
		delete(r.cancels, id)
	}
	r.mu.Unlock()
}

// StopAll cancels all running connectors.
func (r *Registry) StopAll() {
	r.mu.Lock()
	for id, cancel := range r.cancels {
		cancel()
		delete(r.cancels, id)
	}
	r.mu.Unlock()
}

// LoadAndStart reads all enabled sources from the DB, builds connectors, and starts them.
func (r *Registry) LoadAndStart(ctx context.Context) error {
	sources, err := r.store.ListSources(ctx)
	if err != nil {
		return fmt.Errorf("load sources: %w", err)
	}
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		s := src // capture
		c, err := Build(&s, r.log)
		if err != nil {
			r.log.Warn().Err(err).Str("id", s.ID).Str("connector", s.Connector).Msg("connector build failed — skipping")
			continue
		}
		r.Register(c)
		if err := r.Start(ctx, s.ID); err != nil {
			r.log.Warn().Err(err).Str("id", s.ID).Msg("connector start failed")
		}
	}
	r.log.Info().Int("sources", len(sources)).Msg("connector registry loaded")
	return nil
}

// Healthy returns a map of connector ID → health error (nil = healthy).
func (r *Registry) Healthy(ctx context.Context) map[string]error {
	r.mu.RLock()
	ids := make([]string, 0, len(r.connectors))
	for id := range r.connectors {
		ids = append(ids, id)
	}
	r.mu.RUnlock()

	result := make(map[string]error, len(ids))
	for _, id := range ids {
		r.mu.RLock()
		c, ok := r.connectors[id]
		r.mu.RUnlock()
		if ok {
			result[id] = c.Health(ctx)
		}
	}
	return result
}
