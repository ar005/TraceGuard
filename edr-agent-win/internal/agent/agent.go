// internal/agent/agent.go
// Core agent for Windows — owns lifecycle of all monitors, event bus,
// local buffer, and transport. Start() blocks until ctx is cancelled.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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
	"github.com/youredr/edr-agent-win/internal/forensics"
	"github.com/youredr/edr-agent-win/internal/monitor/yarascan"
	"github.com/youredr/edr-agent-win/internal/selfprotect"
	"github.com/youredr/edr-agent-win/internal/chainid"
	"github.com/youredr/edr-agent-win/internal/tasks"
	"github.com/youredr/edr-agent-win/internal/transport"
	"github.com/youredr/edr-agent-win/internal/version"
	"github.com/youredr/edr-agent-win/internal/versioncheck"
	"github.com/youredr/edr-agent-win/pkg/types"
)

type Agent struct {
	cfg      *config.Config
	log      zerolog.Logger
	agentID  string
	hostname string

	bus           events.Bus
	buf           *buffer.LocalBuffer
	transport     *transport.GRPCTransport
	chainAssigner *chainid.Assigner

	runCtx     context.Context
	fleetCfgMu sync.Mutex

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
	yaraMonitor     *yarascan.Monitor
	selfProtect     *selfprotect.SelfProtect
}

func New(cfg *config.Config) (*Agent, error) {
	hostname, _ := os.Hostname()

	log := logger.New(cfg.Log)

	agentID := cfg.Agent.ID
	if agentID == "" {
		agentID = loadOrGenerateAgentID(cfg.Agent.IDFile, log)
	}

	buildInfo := version.Get()
	log.Info().
		Str("agent_id", agentID).
		Str("hostname", hostname).
		Str("version", buildInfo.Version).
		Str("platform", "windows/amd64").
		Msg("TraceGuard Windows agent initializing")

	logConfigAudit(cfg, log)

	bus := events.NewBus(agentID, hostname)

	// Chain stamper: assigns chain_id to every event before fan-out.
	chainAssigner := chainid.New(agentID)
	bus.SetChainStamper(func(ev events.Event) {
		b, err := json.Marshal(ev)
		if err != nil {
			return
		}
		if id := chainAssigner.Assign(ev.EventType(), b); id != "" {
			ev.SetChainID(id)
		}
	})

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
		APIKey:     cfg.Agent.APIKey,
		AgentID:    agentID,
		Hostname:   hostname,
		Tags:       cfg.Agent.Tags,
		Env:        cfg.Agent.Env,
		Notes:      cfg.Agent.Notes,
	}, log)

	contain := containment.New(cfg.Agent.BackendURL, log)
	contain.RestoreState()
	trans.SetContainment(contain)

	a := &Agent{
		cfg:           cfg,
		log:           log,
		agentID:       agentID,
		hostname:      hostname,
		bus:           bus,
		buf:           buf,
		transport:     trans,
		chainAssigner: chainAssigner,
	}

	trans.OnConfigChange(func(newVer string) {
		go a.fetchAndApplyFleetConfig(newVer)
	})

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

	if cfg.Monitors.YARAScan.Enabled {
		workerCount := cfg.Monitors.YARAScan.WorkerCount
		if workerCount <= 0 {
			workerCount = 2
		}
		a.yaraMonitor = yarascan.New(yarascan.Config{
			Enabled:     true,
			BackendURL:  cfg.Agent.RESTBackendURL,
			APIKey:      cfg.Agent.APIKey,
			WorkerCount: workerCount,
		}, bus, log)
	}

	// Self-protection — always created; Start() decides what to activate.
	a.selfProtect = selfprotect.New(selfprotect.Config{
		BinPath:      cfg.SelfProtect.BinPath,
		Watchdog:     cfg.SelfProtect.Watchdog,
		ImmutableBin: cfg.SelfProtect.ImmutableBin,
	}, log)

	// Apply any persisted fleet config from a previous push.
	if persisted := loadPersistedFleetConfig(log); persisted != nil {
		log.Info().Msg("applying persisted fleet monitor config")
		a.cfg.Monitors = *persisted
	}

	return a, nil
}

func (a *Agent) Start(ctx context.Context) error {
	a.runCtx = ctx

	unsubBuf := a.bus.Subscribe("*", func(ev events.Event) { a.buf.Write(ev) })
	defer unsubBuf()
	unsubTrans := a.bus.Subscribe("*", func(ev events.Event) { a.transport.Send(ev) })
	defer unsubTrans()

	if err := a.transport.Start(ctx); err != nil {
		a.log.Warn().Err(err).Msg("transport start failed; running in offline mode")
	}
	go a.transport.StartLiveResponse(ctx)

	// Periodic version check — warns if agent is older than backend's minimum.
	if a.cfg.Agent.RESTBackendURL != "" {
		vc := versioncheck.New(a.cfg.Agent.RESTBackendURL, a.cfg.Agent.APIKey, a.log)
		go vc.Run(ctx)
	}

	// Self-protection (started before monitors so the binary is protected
	// before we expose any attack surface).
	if err := a.selfProtect.Start(ctx); err != nil {
		a.log.Warn().Err(err).Msg("self-protect start failed — continuing unprotected")
	}

	// Drain tamper notifications from the selfprotect subsystem.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case n := <-a.selfProtect.TamperCh:
				a.log.Error().
					Str("mechanism", n.Mechanism).
					Str("detail", n.Detail).
					Msg("AGENT_TAMPER")
				a.bus.Publish(&agentTamperEvent{
					BaseEvent: types.BaseEvent{
						ID:        uuid.New().String(),
						Type:      types.EventAgentTamper,
						Timestamp: time.Now(),
						AgentID:   a.agentID,
						Hostname:  a.hostname,
						Severity:  types.SeverityCritical,
					},
					Mechanism: n.Mechanism,
					Detail:    n.Detail,
				})
				if a.cfg.Agent.RESTBackendURL != "" {
					go a.reportTamper(n.Mechanism, n.Detail)
				}
			}
		}
	}()

	// Forensics acquisition poll loop — checks for pending jobs every 60s.
	go a.runForensicsPollLoop(ctx)

	// Wire task executor — receives tasks via heartbeat and reports results back.
	taskExec := tasks.New(a.transport, a.log)
	a.transport.OnTask(taskExec.Handle)

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
		{"YARA scanner", a.startMonitor(a.yaraMonitor), a.yaraMonitor != nil},
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

	// Stop monitors concurrently. Each gets a 3-second deadline so a blocked
	// ETW/WMI session (kernel call that ignores context cancellation) cannot
	// hang the whole agent on service stop.
	type namedStopper struct {
		name string
		m    monitor
	}
	stoppers := []namedStopper{
		{"yara", a.yaraMonitor},
		{"winevent", a.wineventMonitor},
		{"fim", a.fimMonitor},
		{"schtask", a.schtaskMonitor},
		{"memmon", a.memMonitor},
		{"share", a.shareMonitor},
		{"pipe", a.pipeMonitor},
		{"usb", a.usbMonitor},
		{"driver", a.driverMonitor},
		{"browser", a.browserMonitor},
		{"vuln", a.vulnMonitor},
		{"command", a.commandMonitor},
		{"auth", a.authMonitor},
		{"dns", a.dnsMonitor},
		{"registry", a.registryMonitor},
		{"file", a.fileMonitor},
		{"network", a.networkMonitor},
		{"process", a.processMonitor},
	}
	var stopWg sync.WaitGroup
	for _, s := range stoppers {
		if s.m == nil {
			continue
		}
		stopWg.Add(1)
		go func(name string, m monitor) {
			defer stopWg.Done()
			stopped := make(chan struct{})
			go func() { m.Stop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(3 * time.Second):
				a.log.Warn().Str("monitor", name).Msg("monitor stop timed out")
			}
		}(s.name, s.m)
	}
	stopWg.Wait()

	a.chainAssigner.Stop()
	a.selfProtect.Stop()
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

const fleetConfigPath = `C:\ProgramData\TraceGuard\fleet-config.json`

func (a *Agent) fetchAndApplyFleetConfig(newVer string) {
	backendURL := a.cfg.Agent.RESTBackendURL
	if backendURL == "" {
		backendURL = a.cfg.Agent.BackendURL
	}
	if backendURL == "" {
		return
	}
	ctx := a.runCtx
	if ctx == nil {
		return
	}

	url := strings.TrimRight(backendURL, "/") + "/api/v1/agents/" + a.agentID + "/fleet-config"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		a.log.Warn().Err(err).Msg("fleet config fetch: build request failed")
		return
	}
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.log.Warn().Err(err).Msg("fleet config fetch failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.log.Warn().Int("status", resp.StatusCode).Msg("fleet config fetch: unexpected status")
		return
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		a.log.Warn().Err(err).Msg("fleet config fetch: read body failed")
		return
	}
	if string(raw) == "{}" || len(raw) == 0 {
		return
	}
	var newCfg config.MonitorsConfig
	if err := json.Unmarshal(raw, &newCfg); err != nil {
		a.log.Warn().Err(err).Msg("fleet config fetch: unmarshal failed")
		return
	}
	a.log.Info().Str("version", newVer).Msg("fleet monitor config received — applying")
	a.applyFleetConfig(newCfg)
	_ = os.WriteFile(fleetConfigPath, raw, 0600)
}

func (a *Agent) applyFleetConfig(newCfg config.MonitorsConfig) {
	a.fleetCfgMu.Lock()
	defer a.fleetCfgMu.Unlock()
	ctx := a.runCtx
	if ctx == nil {
		return
	}

	// Process
	if newCfg.Process.Enabled && a.processMonitor == nil {
		a.processMonitor = process.New(process.Config{MaxAncestryDepth: newCfg.Process.MaxAncestryDepth}, a.bus, a.log)
		if err := a.processMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start process monitor failed")
			a.processMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: process monitor started")
		}
	} else if !newCfg.Process.Enabled && a.processMonitor != nil {
		a.processMonitor.Stop(); a.processMonitor = nil
		a.log.Info().Msg("fleet reload: process monitor stopped")
	}

	// Network
	if newCfg.Network.Enabled && a.networkMonitor == nil {
		a.networkMonitor = network.New(network.Config{IgnoreLocalhost: newCfg.Network.IgnoreLocalhost}, a.bus, a.log)
		if err := a.networkMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start network monitor failed")
			a.networkMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: network monitor started")
		}
	} else if !newCfg.Network.Enabled && a.networkMonitor != nil {
		a.networkMonitor.Stop(); a.networkMonitor = nil
		a.log.Info().Msg("fleet reload: network monitor stopped")
	}

	// File
	if newCfg.File.Enabled && a.fileMonitor == nil {
		a.fileMonitor = file.New(file.Config{WatchPaths: newCfg.File.WatchPaths, HashOnWrite: newCfg.File.HashOnWrite}, a.bus, a.log)
		if err := a.fileMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start file monitor failed")
			a.fileMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: file monitor started")
		}
	} else if !newCfg.File.Enabled && a.fileMonitor != nil {
		a.fileMonitor.Stop(); a.fileMonitor = nil
		a.log.Info().Msg("fleet reload: file monitor stopped")
	}

	// Registry
	if newCfg.Registry.Enabled && a.registryMonitor == nil {
		a.registryMonitor = registry.New(registry.Config{ExtraKeys: newCfg.Registry.ExtraKeys}, a.bus, a.log)
		if err := a.registryMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start registry monitor failed")
			a.registryMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: registry monitor started")
		}
	} else if !newCfg.Registry.Enabled && a.registryMonitor != nil {
		a.registryMonitor.Stop(); a.registryMonitor = nil
		a.log.Info().Msg("fleet reload: registry monitor stopped")
	}

	// DNS
	if newCfg.DNS.Enabled && a.dnsMonitor == nil {
		a.dnsMonitor = dns.New(dns.Config{}, a.bus, a.log)
		if err := a.dnsMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start dns monitor failed")
			a.dnsMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: dns monitor started")
		}
	} else if !newCfg.DNS.Enabled && a.dnsMonitor != nil {
		a.dnsMonitor.Stop(); a.dnsMonitor = nil
		a.log.Info().Msg("fleet reload: dns monitor stopped")
	}

	// Auth
	if newCfg.Auth.Enabled && a.authMonitor == nil {
		a.authMonitor = auth.New(auth.Config{}, a.bus, a.log)
		if err := a.authMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start auth monitor failed")
			a.authMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: auth monitor started")
		}
	} else if !newCfg.Auth.Enabled && a.authMonitor != nil {
		a.authMonitor.Stop(); a.authMonitor = nil
		a.log.Info().Msg("fleet reload: auth monitor stopped")
	}

	// Command
	if newCfg.Command.Enabled && a.commandMonitor == nil {
		a.commandMonitor = command.New(command.Config{}, a.bus, a.log)
		if err := a.commandMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start command monitor failed")
			a.commandMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: command monitor started")
		}
	} else if !newCfg.Command.Enabled && a.commandMonitor != nil {
		a.commandMonitor.Stop(); a.commandMonitor = nil
		a.log.Info().Msg("fleet reload: command monitor stopped")
	}

	// Browser
	if newCfg.Browser.Enabled && a.browserMonitor == nil {
		listenAddr := newCfg.Browser.ListenAddr
		if listenAddr == "" {
			listenAddr = "127.0.0.1:9999"
		}
		a.browserMonitor = browser.New(browser.Config{Enabled: true, ListenAddr: listenAddr}, a.bus, a.log)
		if err := a.browserMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start browser monitor failed")
			a.browserMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: browser monitor started")
		}
	} else if !newCfg.Browser.Enabled && a.browserMonitor != nil {
		a.browserMonitor.Stop(); a.browserMonitor = nil
		a.log.Info().Msg("fleet reload: browser monitor stopped")
	}

	// Driver
	if newCfg.Driver.Enabled && a.driverMonitor == nil {
		pollInterval := newCfg.Driver.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 5
		}
		a.driverMonitor = driver.New(driver.Config{PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.driverMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start driver monitor failed")
			a.driverMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: driver monitor started")
		}
	} else if !newCfg.Driver.Enabled && a.driverMonitor != nil {
		a.driverMonitor.Stop(); a.driverMonitor = nil
		a.log.Info().Msg("fleet reload: driver monitor stopped")
	}

	// USB
	if newCfg.USB.Enabled && a.usbMonitor == nil {
		pollInterval := newCfg.USB.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.usbMonitor = usb.New(usb.Config{PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.usbMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start usb monitor failed")
			a.usbMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: usb monitor started")
		}
	} else if !newCfg.USB.Enabled && a.usbMonitor != nil {
		a.usbMonitor.Stop(); a.usbMonitor = nil
		a.log.Info().Msg("fleet reload: usb monitor stopped")
	}

	// Pipe
	if newCfg.Pipe.Enabled && a.pipeMonitor == nil {
		pollInterval := newCfg.Pipe.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.pipeMonitor = pipe.New(pipe.Config{PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.pipeMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start pipe monitor failed")
			a.pipeMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: pipe monitor started")
		}
	} else if !newCfg.Pipe.Enabled && a.pipeMonitor != nil {
		a.pipeMonitor.Stop(); a.pipeMonitor = nil
		a.log.Info().Msg("fleet reload: pipe monitor stopped")
	}

	// Share
	if newCfg.Share.Enabled && a.shareMonitor == nil {
		pollInterval := newCfg.Share.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.shareMonitor = share.New(share.Config{PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.shareMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start share monitor failed")
			a.shareMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: share monitor started")
		}
	} else if !newCfg.Share.Enabled && a.shareMonitor != nil {
		a.shareMonitor.Stop(); a.shareMonitor = nil
		a.log.Info().Msg("fleet reload: share monitor stopped")
	}

	// MemMon
	if newCfg.MemMon.Enabled && a.memMonitor == nil {
		pollInterval := newCfg.MemMon.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 15
		}
		a.memMonitor = memmon.New(memmon.Config{PollIntervalS: pollInterval, IgnoreComms: newCfg.MemMon.IgnoreComms}, a.bus, a.log)
		if err := a.memMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start memmon failed")
			a.memMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: memmon started")
		}
	} else if !newCfg.MemMon.Enabled && a.memMonitor != nil {
		a.memMonitor.Stop(); a.memMonitor = nil
		a.log.Info().Msg("fleet reload: memmon stopped")
	}

	// SchTask
	if newCfg.SchTask.Enabled && a.schtaskMonitor == nil {
		pollInterval := newCfg.SchTask.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 30
		}
		a.schtaskMonitor = schtask.New(schtask.Config{PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.schtaskMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start schtask monitor failed")
			a.schtaskMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: schtask monitor started")
		}
	} else if !newCfg.SchTask.Enabled && a.schtaskMonitor != nil {
		a.schtaskMonitor.Stop(); a.schtaskMonitor = nil
		a.log.Info().Msg("fleet reload: schtask monitor stopped")
	}

	// FIM
	if newCfg.FIM.Enabled && a.fimMonitor == nil {
		pollInterval := newCfg.FIM.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 300
		}
		a.fimMonitor = fim.New(fim.Config{
			PollIntervalS: pollInterval,
			WatchPaths:    newCfg.FIM.WatchPaths,
			BaselinePath:  newCfg.FIM.BaselinePath,
			AutoBaseline:  newCfg.FIM.AutoBaseline,
		}, a.bus, a.log)
		if err := a.fimMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start fim monitor failed")
			a.fimMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: fim monitor started")
		}
	} else if !newCfg.FIM.Enabled && a.fimMonitor != nil {
		a.fimMonitor.Stop(); a.fimMonitor = nil
		a.log.Info().Msg("fleet reload: fim monitor stopped")
	}

	// YARAScan
	if newCfg.YARAScan.Enabled && a.yaraMonitor == nil {
		workerCount := newCfg.YARAScan.WorkerCount
		if workerCount <= 0 {
			workerCount = 2
		}
		a.yaraMonitor = yarascan.New(yarascan.Config{
			Enabled:     true,
			BackendURL:  a.cfg.Agent.RESTBackendURL,
			APIKey:      a.cfg.Agent.APIKey,
			WorkerCount: workerCount,
		}, a.bus, a.log)
		if err := a.yaraMonitor.Start(a.runCtx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start YARA scanner failed")
			a.yaraMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: YARA scanner started")
		}
	} else if !newCfg.YARAScan.Enabled && a.yaraMonitor != nil {
		a.yaraMonitor.Stop()
		a.yaraMonitor = nil
		a.log.Info().Msg("fleet reload: YARA scanner stopped")
	}

	a.cfg.Monitors = newCfg
}

func loadPersistedFleetConfig(log zerolog.Logger) *config.MonitorsConfig {
	raw, err := os.ReadFile(fleetConfigPath)
	if err != nil {
		return nil
	}
	if string(raw) == "{}" || len(raw) == 0 {
		return nil
	}
	var cfg config.MonitorsConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Warn().Err(err).Msg("failed to parse persisted fleet config — ignoring")
		return nil
	}
	return &cfg
}

func loadOrGenerateAgentID(path string, log zerolog.Logger) string {
	if path == "" {
		path = `C:\ProgramData\TraceGuard\agent.id`
	}
	if raw, err := os.ReadFile(path); err == nil {
		candidate := strings.TrimSpace(string(raw))
		if _, parseErr := uuid.Parse(candidate); parseErr == nil {
			return candidate
		}
		// File exists but content is not a valid UUID (truncated write, tampering).
		log.Warn().Str("path", path).Msg("agent ID file has invalid content — generating new ID (host continuity broken)")
	} else if os.IsNotExist(err) {
		log.Info().Str("path", path).Msg("agent ID file not found — generating new ID (first run or file was deleted)")
	} else {
		log.Error().Err(err).Str("path", path).Msg("agent ID file unreadable — generating new ID (host continuity broken)")
	}
	id := uuid.New().String()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Error().Err(err).Str("path", path).Msg("failed to create agent ID directory — ID will not persist across restarts")
		return id
	}
	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		log.Error().Err(err).Str("path", path).Msg("failed to persist agent ID — ID will not persist across restarts")
	}
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

type agentTamperEvent struct {
	types.BaseEvent
	Mechanism string `json:"mechanism"` // "binary_hash" | "debugger"
	Detail    string `json:"detail,omitempty"`
}

func (e *agentTamperEvent) EventType() string { return string(e.Type) }
func (e *agentTamperEvent) EventID() string   { return e.ID }

// ─── Forensics acquisition ────────────────────────────────────────────────────

func (a *Agent) runForensicsPollLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.checkAndExecuteForensicsJobs(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) forensicsBackendURL() string {
	u := a.cfg.Agent.RESTBackendURL
	if u == "" {
		u = a.cfg.Agent.BackendURL
	}
	return u
}

func (a *Agent) checkAndExecuteForensicsJobs(ctx context.Context) {
	backendURL := a.forensicsBackendURL()
	if backendURL == "" {
		return
	}
	pendingURL := strings.TrimRight(backendURL, "/") +
		"/api/v1/agents/" + a.agentID + "/forensics/pending"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pendingURL, nil)
	if err != nil {
		return
	}
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	var result struct {
		Jobs []struct {
			ID      string          `json:"id"`
			JobType string          `json:"job_type"`
			Params  json.RawMessage `json:"params"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	for _, job := range result.Jobs {
		if ctx.Err() != nil {
			return
		}
		a.executeForensicsJob(ctx, backendURL, job.ID, job.JobType, job.Params)
	}
}

func (a *Agent) executeForensicsJob(
	ctx context.Context,
	backendURL, jobID, jobType string,
	params json.RawMessage,
) {
	base := strings.TrimRight(backendURL, "/")

	// Use a generous timeout for full-memory collection.
	collectCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	bundle, err := forensics.Collect(collectCtx, jobType, params)
	if err != nil {
		a.log.Error().Err(err).Str("job", jobID).Msg("forensics collection failed")
		a.reportForensicsError(ctx, base, jobID, err.Error())
		return
	}

	uploadURL := base + "/api/v1/forensics/jobs/" + jobID + "/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL,
		bytes.NewReader(bundle))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Agent-ID", a.agentID)
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}

	uploadClient := &http.Client{Timeout: 5 * time.Minute}
	uploadResp, err := uploadClient.Do(req)
	if err != nil {
		a.log.Error().Err(err).Str("job", jobID).Msg("forensics bundle upload failed")
		return
	}
	defer uploadResp.Body.Close()
	io.Copy(io.Discard, uploadResp.Body)

	a.log.Info().
		Str("job", jobID).
		Str("type", jobType).
		Int("bytes", len(bundle)).
		Msg("forensics bundle uploaded")
}

func (a *Agent) reportForensicsError(
	ctx context.Context,
	baseURL, jobID, errMsg string,
) {
	url := strings.TrimRight(baseURL, "/") +
		"/api/v1/forensics/jobs/" + jobID + "/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewReader(nil))
	if err != nil {
		return
	}
	req.Header.Set("X-Forensics-Error", errMsg)
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// reportTamper POSTs a tamper alert to the backend REST API.
// Called as a goroutine from the TamperCh drain so it never blocks detection.
func (a *Agent) reportTamper(mechanism, description string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	body, _ := json.Marshal(map[string]string{
		"mechanism":   mechanism,
		"description": description,
	})
	url := strings.TrimRight(a.cfg.Agent.RESTBackendURL, "/") +
		"/api/v1/agents/" + a.agentID + "/tamper-alert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		a.log.Warn().Err(err).Msg("tamper-alert: build request failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.log.Warn().Err(err).Msg("tamper-alert: POST failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		a.log.Warn().Int("status", resp.StatusCode).Msg("tamper-alert: unexpected response")
	}
}

// logConfigAudit emits a single structured INFO log summarising the active
// configuration so operators can confirm what was actually loaded.
func logConfigAudit(cfg *config.Config, log zerolog.Logger) {
	m := cfg.Monitors

	var monitors []string
	if m.Process.Enabled  { monitors = append(monitors, "process") }
	if m.Network.Enabled  { monitors = append(monitors, "network") }
	if m.File.Enabled     { monitors = append(monitors, "file") }
	if m.Registry.Enabled { monitors = append(monitors, "registry") }
	if m.DNS.Enabled      { monitors = append(monitors, "dns") }
	if m.Auth.Enabled     { monitors = append(monitors, "auth") }
	if m.Command.Enabled  { monitors = append(monitors, "command") }
	if m.Browser.Enabled  { monitors = append(monitors, "browser") }
	if m.Driver.Enabled   { monitors = append(monitors, "driver") }
	if m.USB.Enabled      { monitors = append(monitors, "usb") }
	if m.Pipe.Enabled     { monitors = append(monitors, "pipe") }
	if m.Share.Enabled    { monitors = append(monitors, "share") }
	if m.MemMon.Enabled   { monitors = append(monitors, "memmon") }
	if m.SchTask.Enabled  { monitors = append(monitors, "schtask") }
	if m.TLSSNI.Enabled   { monitors = append(monitors, "tlssni") }
	if m.FIM.Enabled      { monitors = append(monitors, "fim") }
	if m.Vuln.Enabled     { monitors = append(monitors, "vuln") }
	if m.WinEvent.Enabled { monitors = append(monitors, "winevent") }
	if m.YARAScan.Enabled { monitors = append(monitors, "yarascan") }

	tlsMode := "none"
	if cfg.Agent.TLS.Cert != "" {
		tlsMode = "mTLS"
	} else if cfg.Agent.TLS.Insecure {
		tlsMode = "insecure"
	}

	apiKeyStatus := "[not set]"
	if cfg.Agent.APIKey != "" {
		apiKeyStatus = "[set]"
	}

	log.Info().
		Str("backend_url", cfg.Agent.BackendURL).
		Str("rest_backend_url", cfg.Agent.RESTBackendURL).
		Str("tls_mode", tlsMode).
		Str("api_key", apiKeyStatus).
		Strs("tags", cfg.Agent.Tags).
		Str("env", cfg.Agent.Env).
		Strs("monitors", monitors).
		Str("buffer_path", cfg.Buffer.Path).
		Int("buffer_max_mb", cfg.Buffer.MaxSizeMB).
		Int("buffer_flush_s", cfg.Buffer.FlushIntervalS).
		Str("log_level", cfg.Log.Level).
		Str("log_path", cfg.Log.Path).
		Bool("watchdog", cfg.SelfProtect.Watchdog).
		Bool("immutable_bin", cfg.SelfProtect.ImmutableBin).
		Msg("agent config audit")
}
