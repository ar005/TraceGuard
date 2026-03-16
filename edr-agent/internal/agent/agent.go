// internal/agent/agent.go
//
// Core agent — owns the lifecycle of all monitors, the event bus,
// local buffer, and transport. Start() blocks until ctx is cancelled.

package agent

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/buffer"
	"github.com/youredr/edr-agent/internal/config"
	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/internal/logger"
	"github.com/youredr/edr-agent/internal/monitor/file"
	"github.com/youredr/edr-agent/internal/monitor/network"
	"github.com/youredr/edr-agent/internal/monitor/process"
	"github.com/youredr/edr-agent/internal/monitor/cmd"
	"github.com/youredr/edr-agent/internal/monitor/registry"
	"github.com/youredr/edr-agent/internal/selfprotect"
	"github.com/youredr/edr-agent/internal/transport"
	"github.com/youredr/edr-agent/pkg/types"
)

// Agent is the top-level EDR agent.
type Agent struct {
	cfg      *config.Config
	log      zerolog.Logger
	agentID  string
	hostname string

	bus       events.Bus
	buf       *buffer.LocalBuffer
	transport *transport.GRPCTransport
	protect   *selfprotect.Provider

	processMonitor  *process.Monitor
	networkMonitor  *network.Monitor
	fileMonitor     *file.Monitor
	registryMonitor *registry.Monitor
	cmdMonitor      *cmd.Monitor
}

// New creates a new Agent from configuration.
func New(cfg *config.Config) (*Agent, error) {
	hostname, _ := os.Hostname()

	// Determine or generate agent ID.
	agentID := cfg.Agent.ID
	if agentID == "" {
		agentID = loadOrGenerateAgentID(cfg.Agent.IDFile)
	}

	log := logger.New(cfg.Log)

	log.Info().
		Str("agent_id", agentID).
		Str("hostname", hostname).
		Str("version", Version).
		Msg("EDR agent initializing")

	// Event bus.
	bus := events.NewBus(agentID, hostname)

	// Local buffer (SQLite — survives network outages).
	buf, err := buffer.New(buffer.Config{
		Path:       cfg.Buffer.Path,
		MaxSizeMB:  cfg.Buffer.MaxSizeMB,
		FlushEvery: time.Duration(cfg.Buffer.FlushIntervalS) * time.Second,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("init local buffer: %w", err)
	}

	// Transport (gRPC to backend).
	trans := transport.New(transport.Config{
		BackendURL: cfg.Agent.BackendURL,
		TLSCert:    cfg.Agent.TLS.Cert,
		TLSKey:     cfg.Agent.TLS.Key,
		TLSCA:      cfg.Agent.TLS.CA,
		Insecure:   cfg.Agent.TLS.Insecure,
		AgentID:    agentID,
		Hostname:   hostname,
		Tags:       cfg.Agent.Tags,
		Env:        cfg.Agent.Env,
		Notes:      cfg.Agent.Notes,
	}, log)

	a := &Agent{
		cfg:       cfg,
		log:       log,
		agentID:   agentID,
		hostname:  hostname,
		bus:       bus,
		buf:       buf,
		transport: trans,
	}

	// Wire monitors.
	if cfg.Monitors.Process.Enabled {
		a.processMonitor = process.New(process.DefaultConfig(), bus, log)
	}
	if cfg.Monitors.Network.Enabled {
		a.networkMonitor = network.New(network.DefaultConfig(), bus, log)
	}
	if cfg.Monitors.File.Enabled {
		a.fileMonitor = file.New(file.Config{
			WatchPaths:  cfg.Monitors.File.WatchPaths,
			HashOnWrite: cfg.Monitors.File.HashOnWrite,
		}, bus, log)
	}
	if cfg.Monitors.Registry.Enabled {
		a.registryMonitor = registry.New(registry.DefaultConfig(), bus, log)
	}

	// Command + history monitor.
	a.cmdMonitor = cmd.New(cmd.DefaultConfig(), bus, log, agentID, hostname)

	// Self-protection.
	a.protect = selfprotect.New(selfprotect.Config{
		AgentBinPath: cfg.SelfProtect.BinPath,
		WatchdogMode: cfg.SelfProtect.Watchdog,
	}, bus, log)

	return a, nil
}

// Start runs the agent. Blocks until ctx is cancelled or a fatal error occurs.
func (a *Agent) Start(ctx context.Context) error {
	// Subscribe the buffer and transport to all events.
	unsubBuf := a.bus.Subscribe("*", func(ev events.Event) {
		a.buf.Write(ev)
	})
	defer unsubBuf()

	unsubTrans := a.bus.Subscribe("*", func(ev events.Event) {
		a.transport.Send(ev)
	})
	defer unsubTrans()

	// Start transport (connects to backend, flushes buffer on reconnect).
	if err := a.transport.Start(ctx); err != nil {
		a.log.Warn().Err(err).Msg("transport start failed; running in offline mode")
	}

	// Start self-protection first (so it can protect the other monitors).
	if err := a.protect.Start(ctx); err != nil {
		a.log.Warn().Err(err).Msg("self-protection start failed")
	}

	// Start monitors.
	if a.processMonitor != nil {
		if err := a.processMonitor.Start(ctx); err != nil {
			return fmt.Errorf("start process monitor: %w", err)
		}
		a.log.Info().Msg("process monitor running")
	}
	if a.networkMonitor != nil {
		if err := a.networkMonitor.Start(ctx); err != nil {
			return fmt.Errorf("start network monitor: %w", err)
		}
		a.log.Info().Msg("network monitor running")
	}
	if a.fileMonitor != nil {
		if err := a.fileMonitor.Start(ctx); err != nil {
			return fmt.Errorf("start file monitor: %w", err)
		}
		a.log.Info().Msg("file monitor running")
	}
	if a.registryMonitor != nil {
		if err := a.registryMonitor.Start(ctx); err != nil {
			return fmt.Errorf("start registry monitor: %w", err)
		}
		a.log.Info().Msg("registry monitor running")
	}

	if a.cmdMonitor != nil {
		if err := a.cmdMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("cmd monitor start failed")
		} else {
			a.log.Info().Msg("command & history monitor running")
		}
	}

	// Publish agent start event.
	a.bus.Publish(&agentLifecycleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventAgentStart,
			Timestamp: time.Now(),
			AgentID:   a.agentID,
			Hostname:  a.hostname,
			Severity:  types.SeverityInfo,
		},
		Version: Version,
	})

	// Heartbeat ticker.
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	// Wait for shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case <-ctx.Done():
			return a.shutdown()
		case sig := <-sigCh:
			a.log.Info().Str("signal", sig.String()).Msg("received signal, shutting down")
			return a.shutdown()
		case <-heartbeat.C:
			a.sendHeartbeat()
		}
	}
}

func (a *Agent) shutdown() error {
	a.log.Info().Msg("agent shutting down")

	a.bus.Publish(&agentLifecycleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventAgentStop,
			Timestamp: time.Now(),
			AgentID:   a.agentID,
			Hostname:  a.hostname,
			Severity:  types.SeverityInfo,
		},
	})

	// Give transport a moment to flush the stop event.
	time.Sleep(500 * time.Millisecond)

	// Stop monitors in reverse order.
	if a.cmdMonitor != nil {
		a.cmdMonitor.Stop()
	}
	if a.registryMonitor != nil {
		a.registryMonitor.Stop()
	}
	if a.fileMonitor != nil {
		a.fileMonitor.Stop()
	}
	if a.networkMonitor != nil {
		a.networkMonitor.Stop()
	}
	if a.processMonitor != nil {
		a.processMonitor.Stop()
	}
	if a.protect != nil {
		a.protect.Stop()
	}

	a.transport.Stop()
	a.buf.Close()

	stats := a.bus.Stats()
	a.log.Info().
		Uint64("events_published", stats.Published).
		Uint64("events_dropped", stats.Dropped).
		Msg("agent shutdown complete")

	return nil
}

func (a *Agent) sendHeartbeat() {
	stats := a.bus.Stats()
	a.bus.Publish(&agentLifecycleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventAgentHeartbeat,
			Timestamp: time.Now(),
			AgentID:   a.agentID,
			Hostname:  a.hostname,
			Severity:  types.SeverityInfo,
		},
		EventsPublished: stats.Published,
		EventsDropped:   stats.Dropped,
	})
}

// loadOrGenerateAgentID reads agent ID from disk or creates a new UUID.
func loadOrGenerateAgentID(path string) string {
	if path == "" {
		path = "/var/lib/edr/agent.id"
	}
	if raw, err := os.ReadFile(path); err == nil {
		id := string(raw)
		if len(id) > 0 {
			return id
		}
	}
	id := uuid.New().String()
	_ = os.MkdirAll("/var/lib/edr", 0700)
	_ = os.WriteFile(path, []byte(id), 0600)
	return id
}

// Version is set at build time via -ldflags.
var Version = "dev"

// ─── Agent lifecycle event (internal) ────────────────────────────────────────

type agentLifecycleEvent struct {
	types.BaseEvent
	Version         string `json:"version,omitempty"`
	EventsPublished uint64 `json:"events_published,omitempty"`
	EventsDropped   uint64 `json:"events_dropped,omitempty"`
}

func (e *agentLifecycleEvent) EventType() string { return string(e.Type) }
func (e *agentLifecycleEvent) EventID() string   { return e.ID }
