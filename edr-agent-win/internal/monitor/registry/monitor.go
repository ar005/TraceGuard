//go:build windows

// internal/monitor/registry/monitor.go
// Registry monitor for Windows.
//
// Primary path: ETW Microsoft-Windows-Kernel-Registry fires for every
// SetValueKey, CreateKey, DeleteValueKey, and DeleteKey call system-wide.
// Events are filtered to persistence-critical subtrees in the callback,
// eliminating the 10-second polling lag and adding PID attribution.
//
// The ETW provider fires for ALL registry activity on the machine.
// Filter cost is a simple case-insensitive prefix check — negligible
// compared to the kernel event delivery overhead.
//
// Fallback: if ETW session creation fails (insufficient privilege or
// Windows Server 2012 R2), degrades to the original 10-second polling
// of the six hardcoded persistence keys.

package registry

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows/registry"

	"github.com/youredr/edr-agent-win/internal/etw"
	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// watchedEntry defines a registry subtree to monitor, expressed as a
// lowercased NT object-manager path prefix and an optional infix that
// must also appear in the path. The infix is used for HKCU paths where
// the NT prefix includes a per-user SID that we cannot know at compile time.
type watchedEntry struct {
	prefix   string
	infix    string
	category string
}

// watchedPaths lists the NT-format registry subtrees we care about.
// ETW fires system-wide; isWatched filters to these entries only.
var watchedPaths = []watchedEntry{
	{`\registry\machine\software\microsoft\windows\currentversion\run`, "", "autostart"},
	{`\registry\machine\software\microsoft\windows\currentversion\runonce`, "", "autostart"},
	{`\registry\machine\system\currentcontrolset\services`, "", "service"},
	{`\registry\machine\software\microsoft\windows nt\currentversion\winlogon`, "", "winlogon"},
	// HKCU paths: NT format is \REGISTRY\USER\<SID>\<path>; match any SID by
	// requiring only that the path starts with \registry\user\ AND contains the
	// Run/RunOnce suffix — avoids flooding with unrelated HKCU writes.
	{`\registry\user\`, `\software\microsoft\windows\currentversion\run`, "autostart"},
}

// Config for the registry monitor.
type Config struct {
	ExtraKeys []string // additional Win32 paths to watch (reserved for future use)
}

// Monitor watches registry persistence locations for real-time change events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	sess   *etw.Session
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a registry monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "registry").Logger(),
	}
}

// Start subscribes to Microsoft-Windows-Kernel-Registry ETW events and
// filters to persistence-critical subtrees. Falls back to 10-second polling
// if the ETW session cannot be created.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	sess, err := etw.NewSession("TraceGuard-Registry")
	if err != nil {
		m.log.Warn().Err(err).Msg("ETW session unavailable, falling back to polling")
		return m.startPolling(ctx)
	}

	if err := sess.EnableProvider(etw.GUIDKernelRegistry, etw.TraceLevelInformation, 0xFFFFFFFFFFFFFFFF); err != nil {
		sess.Close()
		m.log.Warn().Err(err).Msg("ETW provider enable failed, falling back to polling")
		return m.startPolling(ctx)
	}

	sess.Subscribe(etw.GUIDKernelRegistry, m.handleETWEvent)
	m.sess = sess

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := sess.Consume(ctx); err != nil && ctx.Err() == nil {
			m.log.Error().Err(err).Msg("ETW consume error")
		}
	}()

	m.log.Info().Msg("registry monitor started (ETW Microsoft-Windows-Kernel-Registry)")
	return nil
}

// Stop cancels the ETW session (or polling context) and waits for goroutines to finish.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.sess != nil {
		m.sess.Close()
	}
	m.wg.Wait()
	m.log.Info().Msg("registry monitor stopped")
}

// handleETWEvent processes Kernel-Registry events 1 (SetValue), 2 (DeleteValue),
// 3 (CreateKey), and 5 (DeleteKey). Called from the ETW dispatch goroutine —
// must return quickly; no blocking calls.
func (m *Monitor) handleETWEvent(ev etw.Event) {
	switch ev.EventID {
	case etw.EventRegSetValue, etw.EventRegDeleteValue, etw.EventRegCreateKey, etw.EventRegDeleteKey:
	default:
		return
	}

	keyPath, valueName, ok := parseRegPayload(ev.EventID, ev.UserData)
	if !ok {
		return
	}

	category, matched := m.matchWatched(keyPath)
	if !matched {
		return
	}

	severity := types.SeverityMedium
	if category == "service" || category == "winlogon" {
		severity = types.SeverityHigh
	}

	evType := types.EventRegistrySet
	if ev.EventID == etw.EventRegDeleteValue || ev.EventID == etw.EventRegDeleteKey {
		evType = types.EventRegistryDelete
	}

	win32Path := regNTPathToWin32(keyPath)

	m.bus.Publish(&types.RegistryEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      evType,
			Timestamp: ev.Timestamp,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      []string{"persistence", category},
			Process:   types.ProcessContext{PID: ev.ProcessID},
		},
		Path:      win32Path,
		ValueName: valueName,
		Category:  category,
	})

	m.log.Info().Str("path", win32Path).Str("value", valueName).
		Uint32("pid", ev.ProcessID).Msg("registry change (ETW)")
}

// matchWatched returns the category for ntPath and true if it falls under a
// watched subtree, or ("", false) if it should be ignored.
func (m *Monitor) matchWatched(ntPath string) (string, bool) {
	lower := strings.ToLower(ntPath)
	for _, wp := range watchedPaths {
		if !strings.HasPrefix(lower, wp.prefix) {
			continue
		}
		if wp.infix != "" && !strings.Contains(lower, wp.infix) {
			continue
		}
		return wp.category, true
	}
	return "", false
}

// ── Polling fallback ──────────────────────────────────────────────────────────
// Preserved from original implementation; activated when ETW session fails.

// watchedKey defines a registry key to monitor along with its root hive.
type watchedKey struct {
	Root     registry.Key
	RootName string
	Path     string
	Category string
}

var defaultKeys = []watchedKey{
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "autostart"},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "autostart"},
	{registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Services`, "service"},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "winlogon"},
	{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "autostart"},
	{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "autostart"},
}

// regKeySnapshot stores all values under a watched key.
type regKeySnapshot struct {
	Values map[string]string
}

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("registry monitor started (polling persistence keys)")
	return nil
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	baselines := make(map[string]*regKeySnapshot)
	for _, wk := range defaultKeys {
		id := wk.RootName + `\` + wk.Path
		baselines[id] = m.snapshotKey(wk)
	}
	m.log.Debug().Int("watched_keys", len(baselines)).Msg("registry baseline captured")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, wk := range defaultKeys {
				id := wk.RootName + `\` + wk.Path
				current := m.snapshotKey(wk)
				prev := baselines[id]
				if prev == nil {
					baselines[id] = current
					continue
				}
				for name, val := range current.Values {
					oldVal, existed := prev.Values[name]
					if !existed {
						m.emitRegSet(wk, name, "", val)
					} else if val != oldVal {
						m.emitRegSet(wk, name, oldVal, val)
					}
				}
				for name, oldVal := range prev.Values {
					if _, exists := current.Values[name]; !exists {
						m.emitRegDelete(wk, name, oldVal)
					}
				}
				baselines[id] = current
			}
		}
	}
}

func (m *Monitor) snapshotKey(wk watchedKey) *regKeySnapshot {
	snap := &regKeySnapshot{Values: make(map[string]string)}
	k, err := registry.OpenKey(wk.Root, wk.Path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return snap
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return snap
	}
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			ival, _, ierr := k.GetIntegerValue(name)
			if ierr == nil {
				val = fmt.Sprintf("%d", ival)
			} else {
				val = "(binary)"
			}
		}
		snap.Values[name] = val
	}
	return snap
}

func (m *Monitor) emitRegSet(wk watchedKey, valueName, oldValue, newValue string) {
	keyPath := wk.RootName + `\` + wk.Path
	severity := types.SeverityMedium
	if wk.Category == "service" || wk.Category == "winlogon" {
		severity = types.SeverityHigh
	}
	m.bus.Publish(&types.RegistryEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventRegistrySet,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      []string{"persistence", wk.Category},
		},
		Path:      keyPath,
		ValueName: valueName,
		OldValue:  oldValue,
		NewValue:  newValue,
		Category:  wk.Category,
	})
	m.log.Info().Str("key", keyPath).Str("value", valueName).Msg("registry change detected")
}

func (m *Monitor) emitRegDelete(wk watchedKey, valueName, oldValue string) {
	keyPath := wk.RootName + `\` + wk.Path
	m.bus.Publish(&types.RegistryEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventRegistryDelete,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityMedium,
			Tags:      []string{"persistence", wk.Category},
		},
		Path:      keyPath,
		ValueName: valueName,
		OldValue:  oldValue,
		Category:  wk.Category,
	})
	m.log.Info().Str("key", keyPath).Str("value", valueName).Msg("registry value deleted")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
