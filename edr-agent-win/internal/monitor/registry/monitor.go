// internal/monitor/registry/monitor.go
// Registry monitor for Windows — polls persistence-critical registry keys.
// Future: ETW Microsoft-Windows-Kernel-Registry for real-time events.
//
// Watches Run/RunOnce/Services/Winlogon keys for changes that indicate
// persistence mechanisms (T1547.001, T1543.003).

package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows/registry"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// watchedKey defines a registry key to monitor along with its root hive.
type watchedKey struct {
	Root     registry.Key
	RootName string
	Path     string
	Category string
}

// defaultKeys are the persistence-critical registry paths.
var defaultKeys = []watchedKey{
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "autostart"},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "autostart"},
	{registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Services`, "service"},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "winlogon"},
	{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "autostart"},
	{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "autostart"},
}

// Config for the registry monitor.
type Config struct {
	ExtraKeys []string
}

// Monitor polls registry persistence locations for changes.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
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

// regValue stores a snapshot of a single registry value.
type regValue struct {
	Name  string
	Value string
}

// regKeySnapshot stores all values under a watched key.
type regKeySnapshot struct {
	Values map[string]string // value name -> data
}

// Start begins polling registry keys.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("registry monitor started (polling persistence keys)")
	return nil
}

// Stop halts the registry monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("registry monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// keyID -> snapshot
	baselines := make(map[string]*regKeySnapshot)

	// Build initial baseline.
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

				// Detect new or changed values.
				for name, val := range current.Values {
					oldVal, existed := prev.Values[name]
					if !existed {
						m.emitRegSet(wk, name, "", val)
					} else if val != oldVal {
						m.emitRegSet(wk, name, oldVal, val)
					}
				}

				// Detect deleted values.
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
			// Try reading as integer.
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

	ev := &types.RegistryEvent{
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
	}

	m.bus.Publish(ev)
	m.log.Info().Str("key", keyPath).Str("value", valueName).Msg("registry change detected")
}

func (m *Monitor) emitRegDelete(wk watchedKey, valueName, oldValue string) {
	keyPath := wk.RootName + `\` + wk.Path

	ev := &types.RegistryEvent{
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
	}

	m.bus.Publish(ev)
	m.log.Info().Str("key", keyPath).Str("value", valueName).Msg("registry value deleted")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
