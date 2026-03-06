// internal/monitor/registry/monitor.go
// Linux "Registry" Monitor — watches critical config files with inotify.
// Tracks: /etc/passwd, /etc/shadow, /etc/sudoers, cron dirs, SSH config,
// ld.so.conf, systemd unit dirs, PAM config.
// Full implementation in the next build phase.

package registry

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-agent/internal/events"
)

// BuiltinPaths are always monitored regardless of config.
var BuiltinPaths = []string{
	// Authentication & authorization
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/pam.d",

	// SSH
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_config",
	"/root/.ssh",

	// Cron / scheduled tasks (persistence vectors)
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/var/spool/cron",

	// Dynamic linker (LD_PRELOAD hijack)
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/etc/ld.so.preload",

	// Systemd (persistence)
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",

	// Init scripts
	"/etc/init.d",
	"/etc/rc.local",
	"/etc/rc.d",

	// Environment
	"/etc/environment",
	"/etc/profile",
	"/etc/profile.d",
	"/etc/bash.bashrc",
}

type Config struct {
	ExtraPaths []string
}

func DefaultConfig() Config {
	return Config{}
}

type Monitor struct {
	cfg Config
	bus events.Bus
	log zerolog.Logger
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{cfg: cfg, bus: bus, log: log.With().Str("monitor", "registry").Logger()}
}

func (m *Monitor) Start(ctx context.Context) error {
	paths := append(BuiltinPaths, m.cfg.ExtraPaths...)
	m.log.Info().Int("paths", len(paths)).Msg("registry monitor started (stub)")
	return nil
}

func (m *Monitor) Stop() {
	m.log.Info().Msg("registry monitor stopped")
}
