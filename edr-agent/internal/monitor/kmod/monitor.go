// Package kmod monitors kernel module loads and unloads by polling /proc/modules.
// Emits KERNEL_MODULE_LOAD and KERNEL_MODULE_UNLOAD events.

package kmod

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// moduleInfo holds parsed info for a single loaded kernel module.
type moduleInfo struct {
	Name string
	Size int64
}

// Config for the kernel module monitor.
type Config struct {
	Enabled       bool
	PollIntervalS int // default 5
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{Enabled: true, PollIntervalS: 5}
}

// Monitor polls /proc/modules to detect kernel module load/unload events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a new kernel module monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 5
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "kmod").Logger(),
		stopCh: make(chan struct{}),
	}
}

// Start begins polling /proc/modules for changes.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("kernel module monitor disabled")
		return nil
	}

	// Take initial baseline snapshot.
	baseline, err := readProcModules()
	if err != nil {
		return fmt.Errorf("initial /proc/modules read: %w", err)
	}
	m.log.Info().Int("modules", len(baseline)).Msg("kernel module monitor baseline captured")

	m.wg.Add(1)
	go m.pollLoop(ctx, baseline)
	return nil
}

// Stop signals the monitor to shut down and waits for completion.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Monitor) pollLoop(ctx context.Context, baseline map[string]moduleInfo) {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			current, err := readProcModules()
			if err != nil {
				m.log.Error().Err(err).Msg("failed to read /proc/modules")
				continue
			}

			m.log.Debug().Int("modules", len(current)).Msg("polled /proc/modules")

			// Detect new modules (loads).
			for name, info := range current {
				if _, existed := baseline[name]; !existed {
					m.log.Warn().Str("module", name).Int64("size", info.Size).Msg("kernel module loaded")
					m.emitEvent(types.EventKernelModuleLoad, info)
				}
			}

			// Detect removed modules (unloads).
			for name, info := range baseline {
				if _, exists := current[name]; !exists {
					m.log.Warn().Str("module", name).Msg("kernel module unloaded")
					m.emitEvent(types.EventKernelModuleUnload, info)
				}
			}

			// Update baseline.
			baseline = current
		}
	}
}

func (m *Monitor) emitEvent(eventType types.EventType, info moduleInfo) {
	ev := &types.KernelModuleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      eventType,
			Timestamp: time.Now(),
			Severity:  types.SeverityMedium,
		},
		ModuleName: info.Name,
		Size:       info.Size,
		Tainted:    isTainted(),
	}

	// For loads, try to find the .ko file path.
	if eventType == types.EventKernelModuleLoad {
		ev.FilePath = findModulePath(info.Name)
		ev.Signed = isModuleSigned(info.Name)
	}

	m.bus.Publish(ev)
}

// readProcModules reads /proc/modules and returns a map of module name -> moduleInfo.
func readProcModules() (map[string]moduleInfo, error) {
	// Format: name size refcount deps state addr [tainted]
	// Example: "ext4 761856 1 - Live 0xffffffffc0..."
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("open /proc/modules: %w", err)
	}
	defer f.Close()

	modules := make(map[string]moduleInfo)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		size, _ := strconv.ParseInt(fields[1], 10, 64)
		modules[name] = moduleInfo{Name: name, Size: size}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan /proc/modules: %w", err)
	}
	return modules, nil
}

// isTainted checks whether the kernel is tainted by reading /proc/sys/kernel/tainted.
func isTainted() bool {
	data, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return false
	}
	val := strings.TrimSpace(string(data))
	return val != "0"
}

// findModulePath tries to locate the .ko file for a given module name
// under /lib/modules/$(uname -r)/.
func findModulePath(name string) string {
	uname, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	kernelVer := strings.TrimSpace(string(uname))
	base := filepath.Join("/lib/modules", kernelVer)

	// Try common compressed and uncompressed suffixes.
	for _, suffix := range []string{".ko", ".ko.zst", ".ko.xz", ".ko.gz"} {
		pattern := filepath.Join(base, "**", name+suffix)
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			return matches[0]
		}
	}

	// Fallback: use modinfo which knows the full path.
	out, err := exec.Command("modinfo", "-n", name).Output()
	if err == nil {
		p := strings.TrimSpace(string(out))
		if p != "" && p != "(builtin)" {
			return p
		}
	}

	return ""
}

// isModuleSigned checks whether modinfo reports a signature for the module.
func isModuleSigned(name string) bool {
	out, err := exec.Command("modinfo", "-F", "sig_id", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}
