// internal/agent/agent.go
// Core agent for Windows — owns lifecycle of all monitors, event bus,
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

	"github.com/youredr/edr-agent-win/internal/buffer"
	"github.com/youredr/edr-agent-win/internal/config"
	"github.com/youredr/edr-agent-win/internal/containment"
	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/internal/logger"
	"github.com/youredr/edr-agent-win/internal/monitor/auth"
	"github.com/youredr/edr-agent-win/internal/monitor/browser"
	"github.com/youredr/edr-agent-win/internal/monitor/command"
	"github.com/youredr/edr-agent-win/internal/monitor/dns"
	"github.com/youredr/edr-agent-win/internal/monitor/driver"
	"github.com/youredr/edr-agent-win/internal/monitor/file"
	"github.com/youredr/edr-agent-win/internal/monitor/fim"
	"github.com/youredr/edr-agent-win/internal/monitor/memmon"
	"github.com/youredr/edr-agent-win/internal/monitor/network"
	"github.com/youredr/edr-agent-win/internal/monitor/pipe"
	"github.com/youredr/edr-agent-win/internal/monitor/process"
	"github.com/youredr/edr-agent-win/internal/monitor/registry"
	"github.com/youredr/edr-agent-win/internal/monitor/schtask"
	"github.com/youredr/edr-agent-win/internal/monitor/share"
	"github.com/youredr/edr-agent-win/internal/monitor/usb"
	"github.com/youredr/edr-agent-win/internal/monitor/vuln"
	"github.com/youredr/edr-agent-win/internal/monitor/winevent"
	"github.com/youredr/edr-agent-win/internal/transport"
	"github.com/youredr/edr-agent-win/internal/version"
	"github.com/youredr/edr-agent-win/pkg/types"
)

type Agent struct {
	cfg      *config.Config
	log      zerolog.Logger
	agentID  string
	hostname string

	bus       events.Bus
	buf       *buffer.LocalBuffer
	transport *transport.GRPCTransport

	processMonitor  *process.Monitor
	networkMonitor  *network.Monitor
	fileMonitor     *file.Monitor
	registryMonitor *registry.Monitor
	dnsMonitor      *dns.Monitor
	authMonitor     *auth.Monitor
	commandMonitor  *command.Monitor
	vulnMonitor     *vuln.Monitor
	browserMonitor  *browser.Monitor
	driverMonitor   *driver.Monitor
	usbMonitor      *usb.Monitor
	pipeMonitor     *pipe.Monitor
	shareMonitor    *share.Monitor
	memMonitor      *memmon.Monitor
	schtaskMonitor  *schtask.Monitor
	fimMonitor      *fim.Monitor
	wineventMonitor *winevent.Monitor
}

func New(cfg *config.Config) (*Agent, error) {
	hostname, _ := os.Hostname()

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
		Str("platform", "windows/amd64").
		Msg("TraceGuard Windows agent initializing")

	bus := events.NewBus(agentID, hostname)

	buf, err := buffer.New(buffer.Config{
		Path:       cfg.Buffer.Path,
		MaxSizeMB:  cfg.Buffer.MaxSizeMB,
		FlushEvery: time.Duration(cfg.Buffer.FlushIntervalS) * time.Second,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("init local buffer: %w", err)
	}

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

	trans.OnConfigChange(func(newVer string) {
		log.Info().Str("version", newVer).Msg("config update received from backend")
	})

	contain := containment.New(cfg.Agent.BackendURL, log)
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

	// ── Wire monitors ──

	if cfg.Monitors.Process.Enabled {
		a.processMonitor = process.New(process.Config{
			MaxAncestryDepth: cfg.Monitors.Process.MaxAncestryDepth,
		}, bus, log)
	}
	if cfg.Monitors.Network.Enabled {
		a.networkMonitor = network.New(network.Config{
			IgnoreLocalhost: cfg.Monitors.Network.IgnoreLocalhost,
		}, bus, log)
	}
	if cfg.Monitors.File.Enabled {
		a.fileMonitor = file.New(file.Config{
			WatchPaths:  cfg.Monitors.File.WatchPaths,
			HashOnWrite: cfg.Monitors.File.HashOnWrite,
		}, bus, log)
	}
	if cfg.Monitors.Registry.Enabled {
		a.registryMonitor = registry.New(registry.Config{
			ExtraKeys: cfg.Monitors.Registry.ExtraKeys,
		}, bus, log)
	}
	if cfg.Monitors.DNS.Enabled {
		a.dnsMonitor = dns.New(dns.Config{}, bus, log)
	}
	if cfg.Monitors.Auth.Enabled {
		a.authMonitor = auth.New(auth.Config{}, bus, log)
	}
	if cfg.Monitors.Command.Enabled {
		a.commandMonitor = command.New(command.Config{}, bus, log)
	}
	if cfg.Monitors.Vuln.Enabled {
		a.vulnMonitor = vuln.New(vuln.Config{}, bus, log)
	}
	if cfg.Monitors.Browser.Enabled {
		a.browserMonitor = browser.New(browser.Config{
			Enabled:    true,
			ListenAddr: cfg.Monitors.Browser.ListenAddr,
		}, bus, log)
	}
	if cfg.Monitors.Driver.Enabled {
		pollInterval := cfg.Monitors.Driver.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 5
		}
		a.driverMonitor = driver.New(driver.Config{PollIntervalS: pollInterval}, bus, log)
	}
	if cfg.Monitors.USB.Enabled {
		pollInterval := cfg.Monitors.USB.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.usbMonitor = usb.New(usb.Config{PollIntervalS: pollInterval}, bus, log)
	}
	if cfg.Monitors.Pipe.Enabled {
		pollInterval := cfg.Monitors.Pipe.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.pipeMonitor = pipe.New(pipe.Config{PollIntervalS: pollInterval}, bus, log)
	}
	if cfg.Monitors.Share.Enabled {
		pollInterval := cfg.Monitors.Share.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.shareMonitor = share.New(share.Config{PollIntervalS: pollInterval}, bus, log)
	}
	if cfg.Monitors.MemMon.Enabled {
		pollInterval := cfg.Monitors.MemMon.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 15
		}
		a.memMonitor = memmon.New(memmon.Config{
			PollIntervalS: pollInterval,
			IgnoreComms:   cfg.Monitors.MemMon.IgnoreComms,
		}, bus, log)
	}
	if cfg.Monitors.SchTask.Enabled {
		pollInterval := cfg.Monitors.SchTask.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 30
		}
		a.schtaskMonitor = schtask.New(schtask.Config{PollIntervalS: pollInterval}, bus, log)
	}
	if cfg.Monitors.FIM.Enabled {
		pollInterval := cfg.Monitors.FIM.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 300
		}
		a.fimMonitor = fim.New(fim.Config{
			PollIntervalS: pollInterval,
			WatchPaths:    cfg.Monitors.FIM.WatchPaths,
			BaselinePath:  cfg.Monitors.FIM.BaselinePath,
			AutoBaseline:  cfg.Monitors.FIM.AutoBaseline,
		}, bus, log)
	}
	if cfg.Monitors.WinEvent.Enabled {
		pollInterval := cfg.Monitors.WinEvent.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 15
		}
		maxEvents := cfg.Monitors.WinEvent.MaxEventsPerPoll
		if maxEvents <= 0 {
			maxEvents = 100
		}
		var channels []winevent.ChannelConfig
		for _, ch := range cfg.Monitors.WinEvent.Channels {
			channels = append(channels, winevent.ChannelConfig{
				Name:     ch.Name,
				EventIDs: ch.EventIDs,
			})
		}
		a.wineventMonitor = winevent.New(winevent.Config{
			PollIntervalS:    pollInterval,
			Channels:         channels,
			MaxEventsPerPoll: maxEvents,
		}, bus, log)
	}

	return a, nil
}

func (a *Agent) Start(ctx context.Context) error {
	unsubBuf := a.bus.Subscribe("*", func(ev events.Event) { a.buf.Write(ev) })
	defer unsubBuf()
	unsubTrans := a.bus.Subscribe("*", func(ev events.Event) { a.transport.Send(ev) })
	defer unsubTrans()

	if err := a.transport.Start(ctx); err != nil {
		a.log.Warn().Err(err).Msg("transport start failed; running in offline mode")
	}
	go a.transport.StartLiveResponse(ctx)

	// Start all monitors — errors are non-fatal (degraded mode).
	monitors := []struct {
		name    string
		start   func(context.Context) error
		enabled bool
	}{
		{"process (ETW)", a.startMonitor(a.processMonitor), a.processMonitor != nil},
		{"network (ETW)", a.startMonitor(a.networkMonitor), a.networkMonitor != nil},
		{"file (ETW)", a.startMonitor(a.fileMonitor), a.fileMonitor != nil},
		{"registry (ETW)", a.startMonitor(a.registryMonitor), a.registryMonitor != nil},
		{"DNS (ETW)", a.startMonitor(a.dnsMonitor), a.dnsMonitor != nil},
		{"auth (EventLog)", a.startMonitor(a.authMonitor), a.authMonitor != nil},
		{"command (ETW)", a.startMonitor(a.commandMonitor), a.commandMonitor != nil},
		{"vulnerability", a.startMonitor(a.vulnMonitor), a.vulnMonitor != nil},
		{"browser (HTTP)", a.startMonitor(a.browserMonitor), a.browserMonitor != nil},
		{"driver", a.startMonitor(a.driverMonitor), a.driverMonitor != nil},
		{"USB (WMI)", a.startMonitor(a.usbMonitor), a.usbMonitor != nil},
		{"pipe", a.startMonitor(a.pipeMonitor), a.pipeMonitor != nil},
		{"share (WMI)", a.startMonitor(a.shareMonitor), a.shareMonitor != nil},
		{"memmon", a.startMonitor(a.memMonitor), a.memMonitor != nil},
		{"schtask", a.startMonitor(a.schtaskMonitor), a.schtaskMonitor != nil},
		{"FIM", a.startMonitor(a.fimMonitor), a.fimMonitor != nil},
		{"winevent (EventLog)", a.startMonitor(a.wineventMonitor), a.wineventMonitor != nil},
	}

	for _, m := range monitors {
		if !m.enabled {
			continue
		}
		if err := m.start(ctx); err != nil {
			a.log.Warn().Err(err).Str("monitor", m.name).Msg("monitor start failed")
		} else {
			a.log.Info().Str("monitor", m.name).Msg("monitor running")
		}
	}

	// Publish agent start event.
	vi := version.Get()
	a.bus.Publish(&agentLifecycleEvent{
		BaseEvent: types.BaseEvent{
			ID: uuid.New().String(), Type: types.EventAgentStart,
			Timestamp: time.Now(), AgentID: a.agentID, Hostname: a.hostname,
			Severity: types.SeverityInfo,
		},
		Version: vi.Version, GitCommit: vi.GitCommit,
		GitBranch: vi.GitBranch, BuildTime: vi.BuildTime, GoVersion: vi.GoVersion,
	})

	// Heartbeat ticker.
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

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

// Monitor interface for generic startup.
type monitor interface {
	Start(ctx context.Context) error
	Stop()
}

func (a *Agent) startMonitor(m monitor) func(context.Context) error {
	if m == nil {
		return func(ctx context.Context) error { return nil }
	}
	return m.Start
}

func (a *Agent) shutdown() error {
	a.log.Info().Msg("agent shutting down")

	a.bus.Publish(&agentLifecycleEvent{
		BaseEvent: types.BaseEvent{
			ID: uuid.New().String(), Type: types.EventAgentStop,
			Timestamp: time.Now(), AgentID: a.agentID, Hostname: a.hostname,
			Severity: types.SeverityInfo,
		},
	})
	time.Sleep(500 * time.Millisecond)

	// Stop monitors in reverse order.
	stoppers := []monitor{
		a.wineventMonitor, a.fimMonitor, a.schtaskMonitor, a.memMonitor, a.shareMonitor,
		a.pipeMonitor, a.usbMonitor, a.driverMonitor, a.browserMonitor,
		a.vulnMonitor, a.commandMonitor, a.authMonitor, a.dnsMonitor,
		a.registryMonitor, a.fileMonitor, a.networkMonitor, a.processMonitor,
	}
	for _, m := range stoppers {
		if m != nil {
			m.Stop()
		}
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
			ID: uuid.New().String(), Type: types.EventAgentHeartbeat,
			Timestamp: time.Now(), AgentID: a.agentID, Hostname: a.hostname,
			Severity: types.SeverityInfo,
		},
		EventsPublished: stats.Published, EventsDropped: stats.Dropped,
	})
}

func loadOrGenerateAgentID(path string) string {
	if path == "" {
		path = `C:\ProgramData\TraceGuard\agent.id`
	}
	if raw, err := os.ReadFile(path); err == nil {
		if id := string(raw); len(id) > 0 {
			return id
		}
	}
	id := uuid.New().String()
	_ = os.MkdirAll(`C:\ProgramData\TraceGuard`, 0700)
	_ = os.WriteFile(path, []byte(id), 0600)
	return id
}

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
