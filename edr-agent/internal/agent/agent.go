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
	"github.com/youredr/edr-agent/internal/containment"
	"github.com/youredr/edr-agent/internal/config"
	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/internal/logger"
	"github.com/youredr/edr-agent/internal/monitor/auth"
	"github.com/youredr/edr-agent/internal/monitor/browser"
	"github.com/youredr/edr-agent/internal/monitor/cmd"
	"github.com/youredr/edr-agent/internal/monitor/file"
	"github.com/youredr/edr-agent/internal/monitor/kmod"
	"github.com/youredr/edr-agent/internal/monitor/cronmon"
	"github.com/youredr/edr-agent/internal/monitor/memmon"
	"github.com/youredr/edr-agent/internal/monitor/pipemon"
	"github.com/youredr/edr-agent/internal/monitor/sharemount"
	"github.com/youredr/edr-agent/internal/monitor/usb"
	"github.com/youredr/edr-agent/internal/monitor/network"
	"github.com/youredr/edr-agent/internal/monitor/tlssni"
	"github.com/youredr/edr-agent/internal/monitor/process"
	"github.com/youredr/edr-agent/internal/monitor/registry"
	"github.com/youredr/edr-agent/internal/monitor/vuln"
	"github.com/youredr/edr-agent/internal/monitor/yarascan"
	"github.com/youredr/edr-agent/internal/selfprotect"
	"github.com/youredr/edr-agent/internal/transport"
	"github.com/youredr/edr-agent/internal/version"
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

	processMonitor    *process.Monitor
	networkMonitor    *network.Monitor
	fileMonitor       *file.Monitor
	registryMonitor   *registry.Monitor
	cmdMonitor        *cmd.Monitor
	authMonitor       *auth.Monitor
	vulnMonitor       *vuln.Monitor
	browserMonitor    *browser.Monitor
	kmodMonitor       *kmod.Monitor
	usbMonitor        *usb.Monitor
	pipeMonitor       *pipemon.Monitor
	shareMountMonitor *sharemount.Monitor
	memMonitor        *memmon.Monitor
	cronMonitor       *cronmon.Monitor
	tlssniMonitor     *tlssni.Monitor
	yaraScanMonitor   *yarascan.Monitor
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

	buildInfo := version.Get()
	log.Info().
		Str("agent_id", agentID).
		Str("hostname", hostname).
		Str("version", buildInfo.Version).
		Str("commit", buildInfo.GitCommit).
		Str("branch", buildInfo.GitBranch).
		Str("built", buildInfo.BuildTime).
		Str("go", buildInfo.GoVersion).
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

	// Register config-change callback so the agent logs when the backend
	// bumps its policy version (rule/suppression changes).
	trans.OnConfigChange(func(newVer string) {
		log.Info().Str("version", newVer).Msg("config update received from backend — monitors will use updated rules on next detection cycle")
	})

	// Network containment controller.
	contain := containment.New(cfg.Agent.BackendURL, log)
	contain.RestoreState()
	trans.SetContainment(contain)

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
			WatchPaths:       cfg.Monitors.File.WatchPaths,
			HashOnWrite:      cfg.Monitors.File.HashOnWrite,
			CaptureAllWrites: cfg.Monitors.File.CaptureAllWrites,
		}, bus, log)
	}
	if cfg.Monitors.Registry.Enabled {
		a.registryMonitor = registry.New(registry.DefaultConfig(), bus, log)
	}

	// Command + history monitor.
	a.cmdMonitor = cmd.New(cmd.DefaultConfig(), bus, log, agentID, hostname)

	// Auth/login monitor.
	a.authMonitor = auth.New(auth.Config{Enabled: true}, bus, log)

	// Package inventory / vulnerability monitor.
	a.vulnMonitor = vuln.New(vuln.DefaultConfig(), bus, log)

	// Browser monitor (receives events from OEDR browser extension).
	if cfg.Monitors.Browser.Enabled {
		listenAddr := cfg.Monitors.Browser.ListenAddr
		if listenAddr == "" {
			listenAddr = "127.0.0.1:9999"
		}
		a.browserMonitor = browser.New(browser.Config{
			Enabled:    true,
			ListenAddr: listenAddr,
		}, bus, log)
	}

	// Kernel module monitor.
	if cfg.Monitors.KMod.Enabled {
		pollInterval := cfg.Monitors.KMod.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 5
		}
		a.kmodMonitor = kmod.New(kmod.Config{
			Enabled:       true,
			PollIntervalS: pollInterval,
		}, bus, log)
	}

	// USB device monitor.
	if cfg.Monitors.USB.Enabled {
		pollInterval := cfg.Monitors.USB.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.usbMonitor = usb.New(usb.Config{
			Enabled:       true,
			PollIntervalS: pollInterval,
		}, bus, log)
	}

	// Named pipe monitor.
	if cfg.Monitors.Pipe.Enabled {
		pollInterval := cfg.Monitors.Pipe.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		watchPaths := cfg.Monitors.Pipe.WatchPaths
		if len(watchPaths) == 0 {
			watchPaths = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}
		}
		a.pipeMonitor = pipemon.New(pipemon.Config{
			Enabled:       true,
			PollIntervalS: pollInterval,
			WatchPaths:    watchPaths,
		}, bus, log)
	}

	// Network share mount monitor.
	if cfg.Monitors.Share.Enabled {
		pollInterval := cfg.Monitors.Share.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.shareMountMonitor = sharemount.New(sharemount.Config{
			Enabled:       true,
			PollIntervalS: pollInterval,
		}, bus, log)
	}

	// Memory injection monitor.
	if cfg.Monitors.MemMon.Enabled {
		pollInterval := cfg.Monitors.MemMon.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 15
		}
		ignoreComms := cfg.Monitors.MemMon.IgnoreComms
		if len(ignoreComms) == 0 {
			ignoreComms = memmon.DefaultConfig().IgnoreComms
		}
		a.memMonitor = memmon.New(memmon.Config{
			Enabled:       true,
			PollIntervalS: pollInterval,
			IgnoreComms:   ignoreComms,
		}, bus, log)
	}

	// Cron monitor.
	if cfg.Monitors.CronMon.Enabled {
		watchPaths := cfg.Monitors.CronMon.WatchPaths
		if len(watchPaths) == 0 {
			watchPaths = cronmon.DefaultConfig().WatchPaths
		}
		a.cronMonitor = cronmon.New(cronmon.Config{
			Enabled:    true,
			WatchPaths: watchPaths,
		}, bus, log)
	}

	// TLS SNI monitor.
	if cfg.Monitors.TLSSNI.Enabled {
		a.tlssniMonitor = tlssni.New(tlssni.DefaultConfig(), bus, log)
	}

	// YARA file scanner — requires file monitor to be enabled (feeds off FILE_CREATE/FILE_WRITE).
	if cfg.Monitors.YARA.Enabled && cfg.Agent.RESTBackendURL != "" {
		a.yaraScanMonitor = yarascan.New(yarascan.Config{
			Enabled:     true,
			BackendURL:  cfg.Agent.RESTBackendURL,
			APIKey:      cfg.Agent.APIKey,
			WorkerCount: cfg.Monitors.YARA.WorkerCount,
		}, bus, log)
	}

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

	// Start live response client (background goroutine).
	go a.transport.StartLiveResponse(ctx)

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

	if a.authMonitor != nil {
		if err := a.authMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("auth monitor start failed")
		} else {
			a.log.Info().Msg("auth/login monitor running")
		}
	}

	if a.vulnMonitor != nil {
		if err := a.vulnMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("vuln monitor start failed")
		} else {
			a.log.Info().Msg("package inventory / vuln monitor running")
		}
	}

	if a.browserMonitor != nil {
		if err := a.browserMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("browser monitor start failed")
		} else {
			a.log.Info().Msg("browser monitor running")
		}
	}

	if a.kmodMonitor != nil {
		if err := a.kmodMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("kmod monitor start failed")
		} else {
			a.log.Info().Msg("kernel module monitor running")
		}
	}

	if a.usbMonitor != nil {
		if err := a.usbMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("usb monitor start failed")
		} else {
			a.log.Info().Msg("USB device monitor running")
		}
	}

	if a.pipeMonitor != nil {
		if err := a.pipeMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("pipe monitor start failed")
		} else {
			a.log.Info().Msg("named pipe monitor running")
		}
	}

	if a.shareMountMonitor != nil {
		if err := a.shareMountMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("share mount monitor start failed")
		} else {
			a.log.Info().Msg("network share monitor running")
		}
	}

	if a.memMonitor != nil {
		if err := a.memMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("memory injection monitor start failed")
		} else {
			a.log.Info().Msg("memory injection monitor running")
		}
	}

	if a.cronMonitor != nil {
		if err := a.cronMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("cron monitor start failed")
		} else {
			a.log.Info().Msg("cron monitor running")
		}
	}

	if a.tlssniMonitor != nil {
		if err := a.tlssniMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("TLS SNI monitor start failed (need root/CAP_NET_RAW)")
		} else {
			a.log.Info().Msg("TLS SNI monitor running")
		}
	}

	if a.yaraScanMonitor != nil {
		go func() {
			if err := a.yaraScanMonitor.Start(ctx); err != nil {
				a.log.Warn().Err(err).Msg("YARA scanner monitor failed")
			}
		}()
		a.log.Info().Msg("YARA scanner monitor running")
	}

	// Publish agent start event with full build info.
	vi := version.Get()
	a.bus.Publish(&agentLifecycleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventAgentStart,
			Timestamp: time.Now(),
			AgentID:   a.agentID,
			Hostname:  a.hostname,
			Severity:  types.SeverityInfo,
		},
		Version:   vi.Version,
		GitCommit: vi.GitCommit,
		GitBranch: vi.GitBranch,
		BuildTime: vi.BuildTime,
		GoVersion: vi.GoVersion,
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
	if a.tlssniMonitor != nil {
		a.tlssniMonitor.Stop()
	}
	if a.cronMonitor != nil {
		a.cronMonitor.Stop()
	}
	if a.memMonitor != nil {
		a.memMonitor.Stop()
	}
	if a.shareMountMonitor != nil {
		a.shareMountMonitor.Stop()
	}
	if a.pipeMonitor != nil {
		a.pipeMonitor.Stop()
	}
	if a.usbMonitor != nil {
		a.usbMonitor.Stop()
	}
	if a.kmodMonitor != nil {
		a.kmodMonitor.Stop()
	}
	if a.browserMonitor != nil {
		a.browserMonitor.Stop()
	}
	if a.vulnMonitor != nil {
		a.vulnMonitor.Stop()
	}
	if a.authMonitor != nil {
		a.authMonitor.Stop()
	}
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
	GitCommit       string `json:"git_commit,omitempty"`
	GitBranch       string `json:"git_branch,omitempty"`
	BuildTime       string `json:"build_time,omitempty"`
	GoVersion       string `json:"go_version,omitempty"`
	EventsPublished uint64 `json:"events_published,omitempty"`
	EventsDropped   uint64 `json:"events_dropped,omitempty"`
}

func (e *agentLifecycleEvent) EventType() string { return string(e.Type) }
func (e *agentLifecycleEvent) EventID() string   { return e.ID }
