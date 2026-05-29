// internal/monitor/vuln/monitor.go
// Vulnerability / package inventory monitor for Windows.
//
// Runs `wmic product get name,version /format:csv` every 24 hours
// and emits a PKG_INVENTORY event with the full list of installed software.

package vuln

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// Config for the vuln monitor.
type Config struct{}

// Monitor periodically inventories installed packages.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a vulnerability / package inventory monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "vuln").Logger(),
	}
}

// Start begins the inventory cycle.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("vuln monitor started (24h inventory cycle)")
	return nil
}

// Stop halts the vuln monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("vuln monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Run initial inventory after a short delay.
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	m.runInventory(ctx)

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runInventory(ctx)
		}
	}
}

func (m *Monitor) runInventory(ctx context.Context) {
	cmdCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "wmic", "product", "get", "name,version", "/format:csv")
	out, err := cmd.Output()
	if err != nil {
		m.log.Error().Err(err).Msg("wmic product inventory failed")
		return
	}

	packages := parseWMICCSV(out)
	if len(packages) == 0 {
		m.log.Warn().Msg("no packages found in wmic output")
		return
	}

	// Get OS version info.
	osVersion := getOSVersion(ctx)

	ev := &types.PkgInventoryEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventPkgInventory,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Tags:      []string{"inventory"},
		},
		Packages:  packages,
		OS:        "windows",
		OSVersion: osVersion,
	}

	m.bus.Publish(ev)
	m.log.Info().Int("packages", len(packages)).Msg("package inventory emitted")
}

// parseWMICCSV parses wmic CSV output.
// Format: Node,Name,Version (first line is header).
func parseWMICCSV(data []byte) []types.PackageInfo {
	var packages []types.PackageInfo

	scanner := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Skip header row.
		if first {
			first = false
			continue
		}

		// CSV: Node,Name,Version
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		version := strings.TrimSpace(parts[2])
		if name == "" {
			continue
		}

		packages = append(packages, types.PackageInfo{
			Name:    name,
			Version: version,
			Arch:    runtime.GOARCH,
		})
	}

	return packages
}

// getOSVersion returns the Windows version string.
func getOSVersion(ctx context.Context) string {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "cmd", "/c", "ver")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	ver := strings.TrimSpace(string(out))
	if ver == "" {
		return "unknown"
	}
	return ver
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
