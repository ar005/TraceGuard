// internal/monitor/tlssni/monitor.go
// TLS SNI monitor — stub that gracefully handles missing Npcap.
//
// When Npcap is available (future): uses gopacket to capture TLS ClientHello
// on port 443 and extract the Server Name Indication (SNI) field.
//
// For v1: logs that Npcap is required and returns nil from Start.

package tlssni

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
)

// Config for the TLS SNI monitor.
type Config struct{}

// Monitor is a stub TLS SNI monitor.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a TLS SNI monitor stub.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "tlssni").Logger(),
	}
}

// Start logs that TLS SNI monitoring requires Npcap and returns nil.
// This is a graceful no-op so the agent can start without Npcap installed.
func (m *Monitor) Start(ctx context.Context) error {
	m.log.Info().Msg("TLS SNI monitor requires Npcap — not available, running as stub")
	m.log.Info().Msg("install Npcap (https://npcap.com) to enable TLS SNI capture")

	// Nothing to do in stub mode.
	// Future implementation will:
	// 1. Check if Npcap is installed (pcap.FindAllDevs)
	// 2. Open capture on all interfaces with BPF "tcp dst port 443"
	// 3. Parse TLS ClientHello to extract SNI
	// 4. Emit NET_TLS_SNI events

	return nil
}

// Stop is a no-op for the stub.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("TLS SNI monitor stopped")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
