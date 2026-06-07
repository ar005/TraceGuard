// internal/agent/agent.go
//
// Core agent — owns the lifecycle of all monitors, the event bus,
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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/buffer"
	"github.com/youredr/edr-agent/internal/chainid"
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
	"github.com/youredr/edr-agent/internal/forensics"
	"github.com/youredr/edr-agent/internal/selfprotect"
	"github.com/youredr/edr-agent/internal/tasks"
	"github.com/youredr/edr-agent/internal/transport"
	"github.com/youredr/edr-agent/internal/version"
	"github.com/youredr/edr-agent/internal/versioncheck"
	"github.com/youredr/edr-agent/pkg/types"
)

// Agent is the top-level EDR agent.
type Agent struct {
	cfg      *config.Config
	log      zerolog.Logger
	agentID  string
	hostname string

	bus          events.Bus
	buf          *buffer.LocalBuffer
	transport    *transport.GRPCTransport
	protect      *selfprotect.Provider
	chainAssigner *chainid.Assigner

	runCtx      context.Context
	fleetCfgMu  sync.Mutex

	processMonitor    *process.Monitor
	networkMonitor    *network.Monitor
	fileMonitor       *file.Monitor
	registryMonitor   *registry.Monitor
	cmdMonitor        *cmd.Monitor
	authMonitor       *auth.Monitor
	vulnMonitor       *vuln.Monitor
	browserMonitor    *browser.Monitor
	historyPoller     *browser.HistoryPoller
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

	logConfigAudit(cfg, log)

	// Event bus.
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
		APIKey:     cfg.Agent.APIKey,
		AgentID:    agentID,
		Hostname:   hostname,
		Tags:       cfg.Agent.Tags,
		Env:        cfg.Agent.Env,
		Notes:      cfg.Agent.Notes,
	}, log)

	// Network containment controller.
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

	// Register config-change callback: fetch fleet monitor config from backend and hot-reload.
	// Must be registered after `a` is initialised so the closure captures a valid pointer.
	trans.OnConfigChange(func(newVer string) {
		go a.fetchAndApplyFleetConfig(newVer)
		go a.fetchAndApplyBrowserPolicy()
	})

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

	// Browser history poller (reads Chrome/Firefox SQLite history files).
	if cfg.Monitors.BrowserHistory.Enabled {
		pollInterval := cfg.Monitors.BrowserHistory.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 300
		}
		a.historyPoller = browser.NewHistoryPoller(browser.HistoryConfig{
			Enabled:       true,
			PollIntervalS: pollInterval,
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
	if cfg.Agent.RESTBackendURL != "" {
		a.protect.SetTamperReporter(a.reportTamper)
	}

	// Apply any persisted fleet config from a previous push (survives restarts).
	if persisted := loadPersistedFleetConfig(log); persisted != nil {
		log.Info().Msg("applying persisted fleet monitor config")
		a.cfg.Monitors = *persisted
	}

	return a, nil
}

// Start runs the agent. Blocks until ctx is cancelled or a fatal error occurs.
func (a *Agent) Start(ctx context.Context) error {
	a.runCtx = ctx

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

	// Periodic version check — warns if agent is older than backend's minimum.
	if a.cfg.Agent.RESTBackendURL != "" {
		vc := versioncheck.New(a.cfg.Agent.RESTBackendURL, a.cfg.Agent.APIKey, a.log)
		go vc.Run(ctx)
	}

	// Forensics acquisition poll loop — checks for pending jobs every 60s.
	go a.runForensicsPollLoop(ctx)

	// Wire task executor — receives tasks via heartbeat and reports results back.
	taskExec := tasks.New(a.transport, a.log)
	a.transport.OnTask(taskExec.Handle)

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

	if a.historyPoller != nil {
		if err := a.historyPoller.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("browser history poller start failed")
		} else {
			a.log.Info().Msg("browser history poller running")
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

	// Wait for shutdown via context cancellation (main handles OS signals).
	for {
		select {
		case <-ctx.Done():
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
	// Hold fleetCfgMu so we don't race with applyFleetConfig setting fields to nil.
	a.fleetCfgMu.Lock()
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
	if a.historyPoller != nil {
		a.historyPoller.Stop()
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
	a.fleetCfgMu.Unlock()

	a.chainAssigner.Stop()
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

const fleetConfigPath = "/var/lib/edr/fleet-config.json"

// fetchAndApplyFleetConfig fetches the current fleet monitor config from the backend
// REST API and applies it by hot-reloading affected monitors.
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

	// Empty config ({}) means no fleet override has been pushed yet.
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

	// Persist so config survives agent restart.
	_ = os.WriteFile(fleetConfigPath, raw, 0600)
}

// applyFleetConfig hot-reloads monitors according to the new MonitorsConfig.
// For each monitor: disabled → stop; enabled → start; config changed → stop+restart.
func (a *Agent) applyFleetConfig(newCfg config.MonitorsConfig) {
	a.fleetCfgMu.Lock()
	defer a.fleetCfgMu.Unlock()

	ctx := a.runCtx
	if ctx == nil {
		return
	}

	// Process monitor.
	if newCfg.Process.Enabled && a.processMonitor == nil {
		a.processMonitor = process.New(process.DefaultConfig(), a.bus, a.log)
		if err := a.processMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start process monitor failed")
			a.processMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: process monitor started")
		}
	} else if !newCfg.Process.Enabled && a.processMonitor != nil {
		a.processMonitor.Stop()
		a.processMonitor = nil
		a.log.Info().Msg("fleet reload: process monitor stopped")
	}

	// Network monitor.
	if newCfg.Network.Enabled && a.networkMonitor == nil {
		a.networkMonitor = network.New(network.DefaultConfig(), a.bus, a.log)
		if err := a.networkMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start network monitor failed")
			a.networkMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: network monitor started")
		}
	} else if !newCfg.Network.Enabled && a.networkMonitor != nil {
		a.networkMonitor.Stop()
		a.networkMonitor = nil
		a.log.Info().Msg("fleet reload: network monitor stopped")
	}

	// File monitor.
	if newCfg.File.Enabled && a.fileMonitor == nil {
		a.fileMonitor = file.New(file.Config{
			WatchPaths:       newCfg.File.WatchPaths,
			HashOnWrite:      newCfg.File.HashOnWrite,
			CaptureAllWrites: newCfg.File.CaptureAllWrites,
		}, a.bus, a.log)
		if err := a.fileMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start file monitor failed")
			a.fileMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: file monitor started")
		}
	} else if !newCfg.File.Enabled && a.fileMonitor != nil {
		a.fileMonitor.Stop()
		a.fileMonitor = nil
		a.log.Info().Msg("fleet reload: file monitor stopped")
	}

	// Registry monitor.
	if newCfg.Registry.Enabled && a.registryMonitor == nil {
		a.registryMonitor = registry.New(registry.DefaultConfig(), a.bus, a.log)
		if err := a.registryMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start registry monitor failed")
			a.registryMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: registry monitor started")
		}
	} else if !newCfg.Registry.Enabled && a.registryMonitor != nil {
		a.registryMonitor.Stop()
		a.registryMonitor = nil
		a.log.Info().Msg("fleet reload: registry monitor stopped")
	}

	// Browser monitor.
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
		a.browserMonitor.Stop()
		a.browserMonitor = nil
		a.log.Info().Msg("fleet reload: browser monitor stopped")
	}

	// KMod monitor.
	if newCfg.KMod.Enabled && a.kmodMonitor == nil {
		pollInterval := newCfg.KMod.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 5
		}
		a.kmodMonitor = kmod.New(kmod.Config{Enabled: true, PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.kmodMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start kmod monitor failed")
			a.kmodMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: kmod monitor started")
		}
	} else if !newCfg.KMod.Enabled && a.kmodMonitor != nil {
		a.kmodMonitor.Stop()
		a.kmodMonitor = nil
		a.log.Info().Msg("fleet reload: kmod monitor stopped")
	}

	// USB monitor.
	if newCfg.USB.Enabled && a.usbMonitor == nil {
		pollInterval := newCfg.USB.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.usbMonitor = usb.New(usb.Config{Enabled: true, PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.usbMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start usb monitor failed")
			a.usbMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: usb monitor started")
		}
	} else if !newCfg.USB.Enabled && a.usbMonitor != nil {
		a.usbMonitor.Stop()
		a.usbMonitor = nil
		a.log.Info().Msg("fleet reload: usb monitor stopped")
	}

	// Pipe monitor.
	if newCfg.Pipe.Enabled && a.pipeMonitor == nil {
		pollInterval := newCfg.Pipe.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		watchPaths := newCfg.Pipe.WatchPaths
		if len(watchPaths) == 0 {
			watchPaths = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}
		}
		a.pipeMonitor = pipemon.New(pipemon.Config{Enabled: true, PollIntervalS: pollInterval, WatchPaths: watchPaths}, a.bus, a.log)
		if err := a.pipeMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start pipe monitor failed")
			a.pipeMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: pipe monitor started")
		}
	} else if !newCfg.Pipe.Enabled && a.pipeMonitor != nil {
		a.pipeMonitor.Stop()
		a.pipeMonitor = nil
		a.log.Info().Msg("fleet reload: pipe monitor stopped")
	}

	// Share mount monitor.
	if newCfg.Share.Enabled && a.shareMountMonitor == nil {
		pollInterval := newCfg.Share.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 10
		}
		a.shareMountMonitor = sharemount.New(sharemount.Config{Enabled: true, PollIntervalS: pollInterval}, a.bus, a.log)
		if err := a.shareMountMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start share mount monitor failed")
			a.shareMountMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: share mount monitor started")
		}
	} else if !newCfg.Share.Enabled && a.shareMountMonitor != nil {
		a.shareMountMonitor.Stop()
		a.shareMountMonitor = nil
		a.log.Info().Msg("fleet reload: share mount monitor stopped")
	}

	// Memory injection monitor.
	if newCfg.MemMon.Enabled && a.memMonitor == nil {
		pollInterval := newCfg.MemMon.PollIntervalS
		if pollInterval <= 0 {
			pollInterval = 15
		}
		ignoreComms := newCfg.MemMon.IgnoreComms
		if len(ignoreComms) == 0 {
			ignoreComms = memmon.DefaultConfig().IgnoreComms
		}
		a.memMonitor = memmon.New(memmon.Config{Enabled: true, PollIntervalS: pollInterval, IgnoreComms: ignoreComms}, a.bus, a.log)
		if err := a.memMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start memmon failed")
			a.memMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: memory injection monitor started")
		}
	} else if !newCfg.MemMon.Enabled && a.memMonitor != nil {
		a.memMonitor.Stop()
		a.memMonitor = nil
		a.log.Info().Msg("fleet reload: memory injection monitor stopped")
	}

	// Cron monitor.
	if newCfg.CronMon.Enabled && a.cronMonitor == nil {
		watchPaths := newCfg.CronMon.WatchPaths
		if len(watchPaths) == 0 {
			watchPaths = cronmon.DefaultConfig().WatchPaths
		}
		a.cronMonitor = cronmon.New(cronmon.Config{Enabled: true, WatchPaths: watchPaths}, a.bus, a.log)
		if err := a.cronMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start cron monitor failed")
			a.cronMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: cron monitor started")
		}
	} else if !newCfg.CronMon.Enabled && a.cronMonitor != nil {
		a.cronMonitor.Stop()
		a.cronMonitor = nil
		a.log.Info().Msg("fleet reload: cron monitor stopped")
	}

	// TLS SNI monitor.
	if newCfg.TLSSNI.Enabled && a.tlssniMonitor == nil {
		a.tlssniMonitor = tlssni.New(tlssni.DefaultConfig(), a.bus, a.log)
		if err := a.tlssniMonitor.Start(ctx); err != nil {
			a.log.Warn().Err(err).Msg("fleet reload: start TLS SNI monitor failed")
			a.tlssniMonitor = nil
		} else {
			a.log.Info().Msg("fleet reload: TLS SNI monitor started")
		}
	} else if !newCfg.TLSSNI.Enabled && a.tlssniMonitor != nil {
		a.tlssniMonitor.Stop()
		a.tlssniMonitor = nil
		a.log.Info().Msg("fleet reload: TLS SNI monitor stopped")
	}

	// YARA scanner.
	backendURL := a.cfg.Agent.RESTBackendURL
	if backendURL == "" {
		backendURL = a.cfg.Agent.BackendURL
	}
	if newCfg.YARA.Enabled && a.yaraScanMonitor == nil && backendURL != "" {
		workerCount := newCfg.YARA.WorkerCount
		a.yaraScanMonitor = yarascan.New(yarascan.Config{
			Enabled:     true,
			BackendURL:  backendURL,
			APIKey:      a.cfg.Agent.APIKey,
			WorkerCount: workerCount,
		}, a.bus, a.log)
		go func() {
			if err := a.yaraScanMonitor.Start(ctx); err != nil {
				a.log.Warn().Err(err).Msg("fleet reload: YARA scanner failed")
			}
		}()
		a.log.Info().Msg("fleet reload: YARA scanner started")
	} else if !newCfg.YARA.Enabled && a.yaraScanMonitor != nil {
		// YARA scanner stops via context cancellation; clear the reference so it
		// won't be restarted and the next reload can create a fresh instance.
		a.yaraScanMonitor = nil
		a.log.Info().Msg("fleet reload: YARA scanner deregistered (stops on next ctx cancel)")
	}

	// Update cached config so startup re-merge stays consistent.
	a.cfg.Monitors = newCfg
}

// loadPersistedFleetConfig reads fleet-config.json (if present) and returns a MonitorsConfig
// to merge over the YAML defaults at startup.
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

// fetchAndApplyBrowserPolicy fetches the compiled allow/block policy from the
// backend and updates the browser monitor at runtime.
func (a *Agent) fetchAndApplyBrowserPolicy() {
	if a.browserMonitor == nil {
		return
	}
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

	url := strings.TrimRight(backendURL, "/") + "/api/v1/browser/policy/compiled"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		a.log.Warn().Err(err).Msg("browser policy fetch: build request failed")
		return
	}
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.log.Warn().Err(err).Msg("browser policy fetch failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.log.Warn().Int("status", resp.StatusCode).Msg("browser policy fetch: unexpected status")
		return
	}

	var compiled struct {
		Allow []string `json:"allow"`
		Block []string `json:"block"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&compiled); err != nil {
		a.log.Warn().Err(err).Msg("browser policy fetch: decode failed")
		return
	}

	a.browserMonitor.UpdatePolicy(browser.Policy{
		Allow: compiled.Allow,
		Block: compiled.Block,
	})
}

// ─── Forensics acquisition ───────────────────────────────────────────────────

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
	pendingURL := strings.TrimRight(backendURL, "/") + "/api/v1/agents/" + a.agentID + "/forensics/pending"

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

func (a *Agent) executeForensicsJob(ctx context.Context, backendURL, jobID, jobType string, params json.RawMessage) {
	base := strings.TrimRight(backendURL, "/")

	// Use a generous timeout for full collection.
	collectCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	bundle, err := forensics.Collect(collectCtx, jobType, params)
	if err != nil {
		a.log.Error().Err(err).Str("job", jobID).Msg("forensics collection failed")
		a.reportForensicsError(ctx, base, jobID, err.Error())
		return
	}

	uploadURL := base + "/api/v1/forensics/jobs/" + jobID + "/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(bundle))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Agent-ID", a.agentID)
	if a.cfg.Agent.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Agent.APIKey)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	uploadResp, err := client.Do(req)
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

// reportTamper POSTs a tamper alert to the backend REST API.
// Called as a goroutine from selfprotect so it never blocks the detection path.
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
	if m.Process.Enabled        { monitors = append(monitors, "process") }
	if m.Network.Enabled        { monitors = append(monitors, "network") }
	if m.File.Enabled           { monitors = append(monitors, "file") }
	if m.Registry.Enabled       { monitors = append(monitors, "registry") }
	if m.Browser.Enabled        { monitors = append(monitors, "browser") }
	if m.BrowserHistory.Enabled { monitors = append(monitors, "browser_history") }
	if m.KMod.Enabled           { monitors = append(monitors, "kmod") }
	if m.USB.Enabled            { monitors = append(monitors, "usb") }
	if m.Pipe.Enabled           { monitors = append(monitors, "pipe") }
	if m.Share.Enabled          { monitors = append(monitors, "share") }
	if m.MemMon.Enabled         { monitors = append(monitors, "memmon") }
	if m.CronMon.Enabled        { monitors = append(monitors, "cronmon") }
	if m.TLSSNI.Enabled         { monitors = append(monitors, "tlssni") }
	if m.YARA.Enabled           { monitors = append(monitors, "yara") }

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

func (a *Agent) reportForensicsError(ctx context.Context, baseURL, jobID, errMsg string) {
	// Mark job as failed by uploading empty body with error header.
	url := strings.TrimRight(baseURL, "/") + "/api/v1/forensics/jobs/" + jobID + "/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(nil))
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
