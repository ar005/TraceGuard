// internal/selfprotect/selfprotect.go
// Self-protection for the Windows agent.
//
// Three active mechanisms:
//   1. SHA-256 binary watchdog — detects binary replacement even when mtime is faked.
//   2. Read-only attribute — sets FILE_ATTRIBUTE_READONLY on the agent binary (opt-in).
//   3. Debugger detection — polls IsDebuggerPresent + CheckRemoteDebuggerPresent.
//
// Tamper notifications are sent to TamperCh; agent.go drains the channel and
// publishes AGENT_TAMPER events to the event bus.
//
// SCM-level automatic restart on crash is configured externally via:
//   sc failure TraceGuard reset=60 actions=restart/5000/restart/10000/restart/30000

package selfprotect

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"
)

// TamperNotification describes a detected tamper event.
type TamperNotification struct {
	Mechanism string // "binary_hash" | "readonly_attr" | "debugger"
	Detail    string
}

// Config for self-protection.
type Config struct {
	BinPath      string // absolute path to the agent binary; uses os.Executable() if empty
	Watchdog     bool   // enable SHA-256 binary hash watchdog
	ImmutableBin bool   // set FILE_ATTRIBUTE_READONLY on the binary at startup
}

// SelfProtect runs active tamper-resistance checks.
type SelfProtect struct {
	cfg     Config
	log     zerolog.Logger
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	binHash [32]byte // SHA-256 baseline captured at Start()

	// Exported notification channel — buffered; agent.go drains it.
	TamperCh chan TamperNotification

	// kernel32 lazy procs loaded once in New().
	modKernel32                    *windows.LazyDLL
	procIsDebuggerPresent          *windows.LazyProc
	procCheckRemoteDebuggerPresent *windows.LazyProc
}

// New creates a SelfProtect instance. Lazy DLL procs are resolved here so any
// load failures surface early. The same lazy-DLL pattern is used in
// monitor/pipe/monitor.go and monitor/process/monitor.go.
func New(cfg Config, log zerolog.Logger) *SelfProtect {
	if cfg.BinPath == "" {
		if exe, err := os.Executable(); err == nil {
			cfg.BinPath = exe
		}
	}
	mod := windows.NewLazySystemDLL("kernel32.dll")
	return &SelfProtect{
		cfg:                            cfg,
		log:                            log.With().Str("component", "selfprotect").Logger(),
		TamperCh:                       make(chan TamperNotification, 16),
		modKernel32:                    mod,
		procIsDebuggerPresent:          mod.NewProc("IsDebuggerPresent"),
		procCheckRemoteDebuggerPresent: mod.NewProc("CheckRemoteDebuggerPresent"),
	}
}

// Start activates all configured protection mechanisms.
// Returns nil even if non-critical mechanisms fail (logged as warnings).
func (sp *SelfProtect) Start(ctx context.Context) error {
	ctx, sp.cancel = context.WithCancel(ctx)

	// 1. Read-only binary attribute.
	if sp.cfg.ImmutableBin && sp.cfg.BinPath != "" {
		if err := setReadOnly(sp.cfg.BinPath); err != nil {
			sp.log.Warn().Err(err).Str("path", sp.cfg.BinPath).
				Msg("selfprotect: SetFileAttributes(READONLY) failed")
		} else {
			sp.log.Info().Str("path", sp.cfg.BinPath).
				Msg("selfprotect: binary marked read-only")
		}
	}

	// 2. SHA-256 baseline + watchdog goroutine.
	if sp.cfg.Watchdog && sp.cfg.BinPath != "" {
		h, err := hashFile(sp.cfg.BinPath)
		if err != nil {
			sp.log.Warn().Err(err).Msg("selfprotect: could not hash binary — watchdog disabled")
		} else {
			sp.binHash = h
			sp.log.Info().
				Str("sha256", fmt.Sprintf("%x", h)).
				Str("path", sp.cfg.BinPath).
				Msg("selfprotect: binary hash baseline set")

			sp.wg.Add(1)
			go sp.watchdogLoop(ctx)
		}
	}

	// 3. Debugger detection goroutine (always active, not opt-in).
	sp.wg.Add(1)
	go sp.debuggerLoop(ctx)

	sp.log.Info().
		Bool("watchdog", sp.cfg.Watchdog).
		Bool("immutable_bin", sp.cfg.ImmutableBin).
		Msg("selfprotect: started")
	return nil
}

// Stop cancels all goroutines and, on graceful shutdown, removes the read-only
// attribute so service updates can proceed.
func (sp *SelfProtect) Stop() {
	if sp.cancel != nil {
		sp.cancel()
	}
	sp.wg.Wait()

	// Remove read-only on clean shutdown so the installer can update the binary.
	if sp.cfg.ImmutableBin && sp.cfg.BinPath != "" {
		_ = clearReadOnly(sp.cfg.BinPath)
	}
	sp.log.Info().Msg("selfprotect: stopped")
}

// ─── Watchdog ─────────────────────────────────────────────────────────────────

func (sp *SelfProtect) watchdogLoop(ctx context.Context) {
	defer sp.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := hashFile(sp.cfg.BinPath)
			if err != nil {
				sp.log.Warn().Err(err).Msg("selfprotect: watchdog hash error")
				continue
			}
			if current != sp.binHash {
				detail := fmt.Sprintf("expected %x, got %x", sp.binHash, current)
				sp.log.Error().Str("detail", detail).
					Msg("SELFPROTECT_TAMPER: binary hash mismatch")
				sp.notify(TamperNotification{
					Mechanism: "binary_hash",
					Detail:    detail,
				})
				// Update baseline so we don't flood on every tick.
				sp.binHash = current
			}
		}
	}
}

// ─── Debugger detection ───────────────────────────────────────────────────────

func (sp *SelfProtect) debuggerLoop(ctx context.Context) {
	defer sp.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if mechanism := sp.detectDebugger(); mechanism != "" {
				sp.log.Error().Str("mechanism", mechanism).
					Msg("SELFPROTECT_TAMPER: debugger detected")
				sp.notify(TamperNotification{
					Mechanism: "debugger",
					Detail:    mechanism,
				})
			}
		}
	}
}

// detectDebugger returns a non-empty string naming the detection mechanism if a
// debugger is found, or empty string if clean.
func (sp *SelfProtect) detectDebugger() string {
	// IsDebuggerPresent — user-mode debugger attached to this process.
	r1, _, _ := sp.procIsDebuggerPresent.Call()
	if r1 != 0 {
		return "IsDebuggerPresent"
	}

	// CheckRemoteDebuggerPresent — remote debugger (e.g. WinDbg kernel attach).
	// GetCurrentProcess() returns pseudo-handle (-1); never close it.
	self, _ := windows.GetCurrentProcess()
	var present int32
	sp.procCheckRemoteDebuggerPresent.Call(
		uintptr(self),
		uintptr(unsafe.Pointer(&present)),
	)
	if present != 0 {
		return "CheckRemoteDebuggerPresent"
	}
	return ""
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (sp *SelfProtect) notify(n TamperNotification) {
	select {
	case sp.TamperCh <- n:
	default:
		// Drop if channel full — agent.go is slow to drain; we already logged.
	}
}

func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func setReadOnly(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attr, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	return windows.SetFileAttributes(p, attr|windows.FILE_ATTRIBUTE_READONLY)
}

func clearReadOnly(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attr, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	return windows.SetFileAttributes(p, attr&^uint32(windows.FILE_ATTRIBUTE_READONLY))
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*SelfProtect)(nil)
