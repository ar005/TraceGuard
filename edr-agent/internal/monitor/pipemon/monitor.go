// Package pipemon monitors named pipes (FIFOs) in watched directories.
// Named pipes are used by malware for C2 channels (Cobalt Strike, PsExec).
// Emits PIPE_CREATE events when new FIFO files appear.

package pipemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// pipeInfo holds metadata about a discovered named pipe.
type pipeInfo struct {
	Path        string
	Permissions os.FileMode
}

// Config for the named pipe monitor.
type Config struct {
	Enabled       bool
	PollIntervalS int      // default 10
	WatchPaths    []string // directories to scan for FIFOs
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		PollIntervalS: 10,
		WatchPaths:    []string{"/tmp", "/var/tmp", "/dev/shm", "/run"},
	}
}

// Monitor polls watched directories for new named pipe (FIFO) files.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a new named pipe monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 10
	}
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "pipemon").Logger(),
		stopCh: make(chan struct{}),
	}
}

// Start begins polling watched directories for named pipes.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("named pipe monitor disabled")
		return nil
	}

	// Take initial baseline snapshot.
	baseline := m.scanAllPaths()
	m.log.Info().Int("pipes", len(baseline)).Strs("watch_paths", m.cfg.WatchPaths).Msg("named pipe monitor baseline captured")

	m.wg.Add(1)
	go m.pollLoop(ctx, baseline)
	return nil
}

// Stop signals the monitor to shut down and waits for completion.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Monitor) pollLoop(ctx context.Context, baseline map[string]pipeInfo) {
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
			current := m.scanAllPaths()

			// Detect new pipes.
			for path, info := range current {
				if _, existed := baseline[path]; !existed {
					m.log.Warn().Str("path", path).Msg("new named pipe detected")
					m.emitEvent(info)
				}
			}

			// Update baseline.
			baseline = current
		}
	}
}

// scanAllPaths walks each watched directory looking for FIFO files.
func (m *Monitor) scanAllPaths() map[string]pipeInfo {
	pipes := make(map[string]pipeInfo)
	for _, dir := range m.cfg.WatchPaths {
		m.scanDir(dir, pipes)
	}
	return pipes
}

// scanDir scans a single directory (non-recursively to limit overhead) for FIFOs.
func (m *Monitor) scanDir(dir string, pipes map[string]pipeInfo) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory may not exist or may not be readable; this is normal.
		return
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		// Check for FIFO (named pipe) mode bit.
		if info.Mode()&os.ModeNamedPipe != 0 {
			fullPath := filepath.Join(dir, entry.Name())
			pipes[fullPath] = pipeInfo{
				Path:        fullPath,
				Permissions: info.Mode().Perm(),
			}
		}
	}
}

func (m *Monitor) emitEvent(info pipeInfo) {
	// Try to find which process created / owns this pipe by scanning /proc/*/fd.
	creatorPID, creatorComm := findPipeCreator(info.Path)

	ev := &types.PipeEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventPipeCreate,
			Timestamp: time.Now(),
			Severity:  types.SeverityMedium,
		},
		PipePath:    info.Path,
		CreatorPID:  creatorPID,
		CreatorComm: creatorComm,
		Permissions: fmt.Sprintf("%04o", info.Permissions),
		Location:    classifyLocation(info.Path),
	}

	m.bus.Publish(ev)
}

// classifyLocation returns a short label for the pipe's directory.
func classifyLocation(path string) string {
	switch {
	case strings.HasPrefix(path, "/dev/shm"):
		return "dev_shm"
	case strings.HasPrefix(path, "/tmp"):
		return "tmp"
	case strings.HasPrefix(path, "/var/tmp"):
		return "tmp"
	case strings.HasPrefix(path, "/run"):
		return "run"
	default:
		return "other"
	}
}

// findPipeCreator scans /proc/*/fd/ for symlinks pointing to the given pipe path
// and returns the owning PID and comm. Returns (0, "") if not found.
func findPipeCreator(pipePath string) (uint32, string) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, ""
	}

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		// Only look at numeric (PID) directories.
		pid := entry.Name()
		if len(pid) == 0 || pid[0] < '0' || pid[0] > '9' {
			continue
		}

		fdDir := filepath.Join("/proc", pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == pipePath {
				// Found the owner — read its comm.
				comm := readComm(pid)
				pidNum := parsePID(pid)
				return pidNum, comm
			}
		}
	}
	return 0, ""
}

// readComm reads the process comm from /proc/[pid]/comm.
func readComm(pid string) string {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// parsePID converts a string PID to uint32.
func parsePID(s string) uint32 {
	var pid uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		pid = pid*10 + uint32(c-'0')
	}
	return pid
}
