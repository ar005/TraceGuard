// internal/monitor/file/monitor.go
// File Integrity Monitor — uses fanotify/inotify to watch critical paths.
// Full implementation in the next build phase.

package file

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-agent/internal/events"
)

type Config struct {
	WatchPaths  []string
	HashOnWrite bool
}

type Monitor struct {
	cfg Config
	bus events.Bus
	log zerolog.Logger
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{cfg: cfg, bus: bus, log: log.With().Str("monitor", "file").Logger()}
}

func (m *Monitor) Start(ctx context.Context) error {
	m.log.Info().Strs("paths", m.cfg.WatchPaths).Msg("file monitor started (stub)")
	return nil
}

func (m *Monitor) Stop() {
	m.log.Info().Msg("file monitor stopped")
}
