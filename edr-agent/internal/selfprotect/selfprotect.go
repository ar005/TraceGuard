// internal/selfprotect/selfprotect.go
//
// Self-Protection Provider.
//
// Responsibilities:
//   1. Watchdog: respawn the agent process if it's killed unexpectedly.
//   2. Anti-tamper: detect and alert on attempts to kill, ptrace, or delete
//      the agent binary.
//   3. Immutable binary: optionally set chattr +i on the agent binary.
//   4. Subscribe to ptrace events from the process monitor and cross-check
//      whether the target PID is our own.

package selfprotect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config controls self-protection behavior.
type Config struct {
	// AgentBinPath is the path to the agent binary (to protect and watch).
	AgentBinPath string

	// WatchdogMode: if true, launch a child watchdog process that re-execs
	// the agent if it dies. (Should be run as a separate systemd ExecStart
	// in production; this is for standalone mode.)
	WatchdogMode bool

	// ImmutableBin: run "chattr +i" on the agent binary at start.
	// Requires root. Will be reversed at clean shutdown.
	ImmutableBin bool
}

// Provider implements self-protection for the agent.
type Provider struct {
	cfg     Config
	bus     events.Bus
	log     zerolog.Logger
	agentPID uint32
	stopCh  chan struct{}
	unsub   func()
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Provider {
	return &Provider{
		cfg:      cfg,
		bus:      bus,
		log:      log.With().Str("component", "selfprotect").Logger(),
		agentPID: uint32(os.Getpid()),
		stopCh:   make(chan struct{}),
	}
}

func (p *Provider) Start(ctx context.Context) error {
	// Detect our own binary path if not configured.
	if p.cfg.AgentBinPath == "" {
		if exe, err := os.Executable(); err == nil {
			p.cfg.AgentBinPath = exe
		}
	}

	// Optionally make the binary immutable.
	if p.cfg.ImmutableBin && p.cfg.AgentBinPath != "" {
		if err := runChattr("+i", p.cfg.AgentBinPath); err != nil {
			p.log.Warn().Err(err).Msg("chattr +i failed — running without immutable binary")
		} else {
			p.log.Info().Str("path", p.cfg.AgentBinPath).Msg("agent binary set immutable")
		}
	}

	// Subscribe to ptrace events so we can detect attacks against our PID.
	p.unsub = p.bus.Subscribe(string(types.EventProcessPtrace), func(ev events.Event) {
		ptraceEv, ok := ev.(*types.ProcessPtraceEvent)
		if !ok {
			return
		}
		if ptraceEv.TargetPID == p.agentPID {
			p.handleTamperAttempt(fmt.Sprintf(
				"ptrace(%s) targeting agent PID %d from PID %d (%s)",
				ptraceRequestName(ptraceEv.PtraceRequest),
				p.agentPID, ptraceEv.Process.PID, ptraceEv.Process.Comm,
			))
		}
	})

	// File watcher on the agent binary.
	if p.cfg.AgentBinPath != "" {
		go p.watchBinary(ctx)
	}

	p.log.Info().Uint32("pid", p.agentPID).Msg("self-protection active")
	return nil
}

func (p *Provider) Stop() {
	close(p.stopCh)
	if p.unsub != nil {
		p.unsub()
	}
	// Remove immutable flag so the binary can be updated.
	if p.cfg.ImmutableBin && p.cfg.AgentBinPath != "" {
		_ = runChattr("-i", p.cfg.AgentBinPath)
	}
}

// watchBinary polls the agent binary for deletion or modification.
// In production, pair with inotify for immediate detection.
func (p *Provider) watchBinary(ctx context.Context) {
	var lastInfo os.FileInfo
	var err error

	if p.cfg.AgentBinPath != "" {
		lastInfo, err = os.Stat(p.cfg.AgentBinPath)
		if err != nil {
			p.log.Warn().Err(err).Msg("cannot stat agent binary")
		}
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if p.cfg.AgentBinPath == "" {
				continue
			}
			info, err := os.Stat(p.cfg.AgentBinPath)
			if err != nil {
				// Binary deleted or unlinked.
				p.handleTamperAttempt(fmt.Sprintf(
					"agent binary %q has been deleted or is inaccessible: %v",
					p.cfg.AgentBinPath, err,
				))
				lastInfo = nil
				continue
			}
			if lastInfo != nil && info.ModTime() != lastInfo.ModTime() {
				p.handleTamperAttempt(fmt.Sprintf(
					"agent binary %q has been modified (mtime changed)",
					p.cfg.AgentBinPath,
				))
			}
			lastInfo = info
		}
	}
}

func (p *Provider) handleTamperAttempt(description string) {
	p.log.Error().Msg("TAMPER ATTEMPT DETECTED: " + description)

	p.bus.Publish(&tamperEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventAgentTamper,
			Timestamp: time.Now(),
			AgentID:   p.bus.AgentID(),
			Hostname:  p.bus.Hostname(),
			Severity:  types.SeverityCritical,
			Tags:      []string{"tamper", "self_protect"},
		},
		Description: description,
		AgentPID:    p.agentPID,
	})
}

func runChattr(flag, path string) error {
	cmd := exec.Command("chattr", flag, path)
	return cmd.Run()
}

func ptraceRequestName(req uint32) string {
	names := map[uint32]string{
		4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA",
		13: "PTRACE_SETREGS", 15: "PTRACE_SETFPREGS",
		16: "PTRACE_ATTACH", 17: "PTRACE_DETACH",
		0x4206: "PTRACE_SEIZE",
	}
	if name, ok := names[req]; ok {
		return name
	}
	return fmt.Sprintf("PTRACE_0x%x", req)
}

// ─── Tamper event type ────────────────────────────────────────────────────────

type tamperEvent struct {
	types.BaseEvent
	Description string `json:"description"`
	AgentPID    uint32 `json:"agent_pid"`
}

func (e *tamperEvent) EventType() string { return string(types.EventAgentTamper) }
func (e *tamperEvent) EventID() string   { return e.ID }

// ─── Watchdog (standalone mode) ───────────────────────────────────────────────
// In production, use systemd Restart=on-failure instead.
// This is for environments where systemd is not available.

// RunWatchdog monitors childPID and re-execs the agent if it dies.
// Call this in a separate goroutine before starting the main agent.
func RunWatchdog(agentBin string, agentArgs []string) {
	for {
		cmd := exec.Command(agentBin, agentArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true, // new process group
		}
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr,
				"[watchdog] agent exited with error: %v — restarting in 3s\n", err)
		} else {
			fmt.Fprintf(os.Stderr,
				"[watchdog] agent exited cleanly — restarting in 3s\n")
		}
		time.Sleep(3 * time.Second)
	}
}
