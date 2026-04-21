// Package memmon detects suspicious memory operations by polling /proc/[pid]/maps
// for anonymous executable memory regions (shellcode indicators).
// Emits MEMORY_INJECT events.

package memmon

import (
	"bufio"
	"context"
	"fmt"
	"os"
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

// region tracks an anonymous executable memory region for a process.
type region struct {
	Address     string
	Size        int64
	Permissions string
}

// Config for the memory injection monitor.
type Config struct {
	Enabled       bool
	PollIntervalS int      // default 15
	IgnoreComms   []string // JIT processes to skip
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		PollIntervalS: 15,
		IgnoreComms: []string{
			"java", "node", "python3", "python", "firefox",
			"chrome", "chromium", "code",
		},
	}
}

// Monitor polls /proc/*/maps to detect anonymous executable memory regions.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup

	// baseline tracks known anonymous exec regions per PID to avoid re-alerting.
	mu       sync.Mutex
	baseline map[uint32]map[string]struct{} // pid -> set of address ranges
}

// New creates a new memory injection monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 15
	}
	return &Monitor{
		cfg:      cfg,
		bus:      bus,
		log:      log.With().Str("monitor", "memmon").Logger(),
		stopCh:   make(chan struct{}),
		baseline: make(map[uint32]map[string]struct{}),
	}
}

// Start begins polling /proc/*/maps for suspicious memory regions.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("memory injection monitor disabled")
		return nil
	}

	m.log.Info().
		Int("poll_interval_s", m.cfg.PollIntervalS).
		Int("ignore_comms", len(m.cfg.IgnoreComms)).
		Msg("memory injection monitor starting")

	m.wg.Add(1)
	go m.pollLoop(ctx)
	return nil
}

// Stop signals the monitor to shut down and waits for completion.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Monitor) pollLoop(ctx context.Context) {
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
			m.scanAllProcesses()
		}
	}
}

// scanAllProcesses iterates over /proc/*/maps looking for anomalies.
func (m *Monitor) scanAllProcesses() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		m.log.Error().Err(err).Msg("failed to read /proc")
		return
	}

	// Track which PIDs are still alive to prune stale baseline entries.
	alivePIDs := make(map[uint32]struct{})

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a numeric PID directory
		}
		pid := uint32(pid64)
		alivePIDs[pid] = struct{}{}

		comm := readComm(pid)
		if m.isIgnored(comm) {
			continue
		}

		m.scanProcess(pid, comm)
	}

	// Prune baseline for dead processes.
	m.mu.Lock()
	for pid := range m.baseline {
		if _, alive := alivePIDs[pid]; !alive {
			delete(m.baseline, pid)
		}
	}
	m.mu.Unlock()
}

// scanProcess reads /proc/<pid>/maps and looks for anonymous executable regions.
func (m *Monitor) scanProcess(pid uint32, comm string) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return // process may have exited
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		region, technique, ok := m.parseMapLine(line)
		if !ok {
			continue
		}

		// Check if we already know about this region for this PID.
		m.mu.Lock()
		if m.baseline[pid] == nil {
			m.baseline[pid] = make(map[string]struct{})
		}
		if _, seen := m.baseline[pid][region.Address]; seen {
			m.mu.Unlock()
			continue
		}
		m.baseline[pid][region.Address] = struct{}{}
		m.mu.Unlock()

		m.emitEvent(pid, comm, region, technique)
	}
}

// parseMapLine checks a single /proc/<pid>/maps line for suspicious patterns.
// Returns the region info, technique name, and whether it was suspicious.
func (m *Monitor) parseMapLine(line string) (region, string, bool) {
	// Format: address perms offset dev inode [pathname]
	// Example: 7f1234000000-7f1234001000 rwxp 00000000 00:00 0
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return region{}, "", false
	}

	addrRange := fields[0]
	perms := fields[1]
	inode := fields[4]

	// We only care about executable regions.
	if !strings.Contains(perms, "x") {
		return region{}, "", false
	}

	// Determine if this is an anonymous mapping.
	// Anonymous mappings have inode 0 and either no pathname or special names.
	pathname := ""
	if len(fields) >= 6 {
		pathname = fields[5]
	}

	isAnonymous := false
	technique := ""

	if inode == "0" && pathname == "" {
		// Completely anonymous executable region — most suspicious.
		isAnonymous = true
		technique = "anonymous_exec"
	} else if inode == "0" && (pathname == "[heap]" || pathname == "[stack]") {
		// Executable heap or stack — very suspicious.
		isAnonymous = true
		technique = "anonymous_exec"
	} else if strings.HasPrefix(pathname, "/memfd:") {
		// memfd_create executable — in-memory file execution.
		isAnonymous = true
		technique = "memfd_exec"
	}

	if !isAnonymous {
		return region{}, "", false
	}

	// rwxp is extra suspicious (read+write+execute).
	if strings.Contains(perms, "r") && strings.Contains(perms, "w") && strings.Contains(perms, "x") {
		technique = "anonymous_exec"
	}

	// Calculate region size from address range.
	size := parseRegionSize(addrRange)

	r := region{
		Address:     addrRange,
		Size:        size,
		Permissions: perms,
	}

	return r, technique, true
}

// parseRegionSize parses "start-end" hex address range and returns size in bytes.
func parseRegionSize(addrRange string) int64 {
	parts := strings.SplitN(addrRange, "-", 2)
	if len(parts) != 2 {
		return 0
	}
	start, err1 := strconv.ParseUint(parts[0], 16, 64)
	end, err2 := strconv.ParseUint(parts[1], 16, 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int64(end - start)
}

func (m *Monitor) emitEvent(pid uint32, comm string, r region, technique string) {
	description := fmt.Sprintf("anonymous executable memory region (%s) detected in process %s (PID %d)",
		r.Permissions, comm, pid)

	severity := types.SeverityHigh
	if technique == "memfd_exec" {
		severity = types.SeverityCritical
		description = fmt.Sprintf("memfd executable mapping detected in process %s (PID %d)", comm, pid)
	}

	ev := &types.MemoryInjectEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventMemoryInject,
			Timestamp: time.Now(),
			Severity:  severity,
			Tags:      []string{"memory-injection", technique},
		},
		TargetPID:   pid,
		TargetComm:  comm,
		Address:     r.Address,
		Size:        r.Size,
		Permissions: r.Permissions,
		Description: description,
		Technique:   technique,
	}

	m.log.Warn().
		Uint32("pid", pid).
		Str("comm", comm).
		Str("address", r.Address).
		Str("permissions", r.Permissions).
		Str("technique", technique).
		Msg("suspicious memory region detected")

	m.bus.Publish(ev)
}

// isIgnored returns true if the process name is in the ignore list (JIT compilers, etc.).
func (m *Monitor) isIgnored(comm string) bool {
	for _, ignored := range m.cfg.IgnoreComms {
		if comm == ignored {
			return true
		}
	}
	return false
}

// readComm reads /proc/<pid>/comm to get the short process name.
func readComm(pid uint32) string {
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
