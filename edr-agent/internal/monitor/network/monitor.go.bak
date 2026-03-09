// internal/monitor/network/monitor.go
// Network monitor — eBPF-based TCP/UDP connection tracker.
// Full implementation in the next build phase.

package network

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-agent/internal/events"
)

type Config struct {
	IgnoreLocalhost bool
	WatchedPorts    []uint16
}

func DefaultConfig() Config {
	return Config{IgnoreLocalhost: true}
}

type Monitor struct {
	cfg  Config
	bus  events.Bus
	log  zerolog.Logger
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{cfg: cfg, bus: bus, log: log.With().Str("monitor", "network").Logger()}
}

func (m *Monitor) Start(ctx context.Context) error {
	m.log.Info().Msg("network monitor started (stub — full eBPF implementation in next phase)")
	return nil
}

func (m *Monitor) Stop() {
	m.log.Info().Msg("network monitor stopped")
}
