// internal/selfprotect/selfprotect.go
// Self-protection stub for Windows — no-op implementation.
//
// On Windows, the agent runs as a Windows Service with automatic recovery
// configured via sc.exe failure settings. This makes userspace self-protection
// unnecessary for v1. The Windows Service Control Manager (SCM) handles:
//   - Automatic restart on crash (sc failure <service> reset=60 actions=restart/60000)
//   - Service dependency ordering
//   - Protected service type (future: PPL with ELAM driver)

package selfprotect

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

// Config for self-protection (unused on Windows v1).
type Config struct {
	BinPath  string
	Watchdog bool
}

// SelfProtect is a no-op stub for Windows.
type SelfProtect struct {
	cfg    Config
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a self-protection stub.
func New(cfg Config, log zerolog.Logger) *SelfProtect {
	return &SelfProtect{
		cfg: cfg,
		log: log.With().Str("component", "selfprotect").Logger(),
	}
}

// Start logs that self-protection relies on Windows SCM and returns nil.
func (sp *SelfProtect) Start(ctx context.Context) error {
	sp.log.Info().Msg("self-protection: using Windows Service recovery (SCM handles restarts)")
	sp.log.Info().Msg("self-protection: configure via: sc failure TraceGuard reset=60 actions=restart/60000/restart/60000/restart/60000")
	return nil
}

// Stop is a no-op.
func (sp *SelfProtect) Stop() {
	if sp.cancel != nil {
		sp.cancel()
	}
	sp.wg.Wait()
	sp.log.Info().Msg("self-protection stopped")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*SelfProtect)(nil)
