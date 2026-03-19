// Package vuln periodically collects installed packages from the endpoint
// and emits a PKG_INVENTORY event for vulnerability matching on the backend.

package vuln

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config for the vulnerability / package inventory monitor.
type Config struct {
	Enabled  bool
	Interval time.Duration // how often to collect (default: 6 hours)
}

// DefaultConfig returns the default vuln monitor configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:  true,
		Interval: 6 * time.Hour,
	}
}

// Monitor periodically collects installed packages and publishes
// PKG_INVENTORY events to the event bus.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a new vuln monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.Interval == 0 {
		cfg.Interval = 6 * time.Hour
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "vuln").Logger(),
		stopCh: make(chan struct{}),
	}
}

// Start begins periodic package inventory collection.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("vuln monitor disabled")
		return nil
	}

	m.log.Info().Dur("interval", m.cfg.Interval).Msg("vuln monitor started")
	m.wg.Add(1)
	go m.loop(ctx)
	return nil
}

// Stop gracefully stops the monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Monitor) loop(ctx context.Context) {
	defer m.wg.Done()

	// Collect once at startup (after a short delay to let other monitors start).
	startDelay := time.NewTimer(30 * time.Second)
	select {
	case <-ctx.Done():
		startDelay.Stop()
		return
	case <-m.stopCh:
		startDelay.Stop()
		return
	case <-startDelay.C:
		m.collect()
	}

	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.collect()
		}
	}
}

func (m *Monitor) collect() {
	osName, osVersion := detectOS()
	var packages []types.PackageInfo
	var err error

	switch {
	case isDebian():
		packages, err = collectDpkg()
	case isRHEL():
		packages, err = collectRPM()
	default:
		m.log.Warn().Msg("unsupported package manager — skipping inventory")
		return
	}

	if err != nil {
		m.log.Error().Err(err).Msg("package collection failed")
		return
	}

	if len(packages) == 0 {
		m.log.Warn().Msg("no packages found")
		return
	}

	ev := &types.PkgInventoryEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventPkgInventory,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
		},
		Packages:  packages,
		OS:        osName,
		OSVersion: osVersion,
	}

	m.log.Info().Int("packages", len(packages)).Str("os", osName).Msg("package inventory collected")
	m.bus.Publish(ev)
}

// isDebian returns true if dpkg-query is available.
func isDebian() bool {
	_, err := exec.LookPath("dpkg-query")
	return err == nil
}

// isRHEL returns true if rpm is available.
func isRHEL() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}

// collectDpkg runs dpkg-query and parses the output.
func collectDpkg() ([]types.PackageInfo, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseTabOutput(string(out)), nil
}

// collectRPM runs rpm -qa and parses the output.
func collectRPM() ([]types.PackageInfo, error) {
	cmd := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseTabOutput(string(out)), nil
}

// parseTabOutput parses tab-delimited "name\tversion\tarch" lines.
func parseTabOutput(data string) []types.PackageInfo {
	var pkgs []types.PackageInfo
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		pkg := types.PackageInfo{
			Name:    parts[0],
			Version: parts[1],
		}
		if len(parts) >= 3 {
			pkg.Arch = parts[2]
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// detectOS reads /etc/os-release to determine OS name and version.
func detectOS() (string, string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "linux", ""
	}
	defer f.Close()

	var name, version string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			name = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	if name == "" {
		name = "linux"
	}
	return name, version
}
