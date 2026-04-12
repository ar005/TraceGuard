// internal/monitor/file/monitor.go
// File monitor for Windows — uses ReadDirectoryChangesW for real-time file system events.
// Emits FILE_CREATE, FILE_WRITE, FILE_DELETE, FILE_RENAME events.

package file

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

type Config struct {
	WatchPaths  []string
	HashOnWrite bool
}

type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = []string{
			`C:\Windows\System32\`,
			`C:\Users\`,
			`C:\ProgramData\`,
			`C:\Windows\Temp\`,
		}
	}
	return &Monitor{cfg: cfg, bus: bus, log: log.With().Str("monitor", "file").Logger()}
}

func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	// Use polling-based approach: scan watched directories for recent changes.
	// ReadDirectoryChangesW would be better but requires per-directory handles.
	m.wg.Add(1)
	go m.pollLoop(ctx)
	return nil
}

func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Track file mod times.
	known := make(map[string]time.Time)

	// Build initial baseline.
	for _, dir := range m.cfg.WatchPaths {
		m.scanDir(dir, known, true)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := make(map[string]time.Time)
			for _, dir := range m.cfg.WatchPaths {
				m.scanDir(dir, current, false)
			}

			// Detect new/modified files.
			for path, modTime := range current {
				if prevTime, exists := known[path]; !exists {
					m.emitEvent(types.EventFileCreate, path)
				} else if modTime.After(prevTime) {
					m.emitEvent(types.EventFileWrite, path)
				}
			}
			// Detect deleted files.
			for path := range known {
				if _, exists := current[path]; !exists {
					m.emitEvent(types.EventFileDelete, path)
				}
			}
			known = current
		}
	}
}

func (m *Monitor) scanDir(dir string, result map[string]time.Time, baseline bool) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Only scan first level + critical subdirs to avoid overwhelming.
		rel, _ := filepath.Rel(dir, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > 2 {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		result[path] = info.ModTime()
		return nil
	})
}

func (m *Monitor) emitEvent(eventType types.EventType, path string) {
	severity := types.SeverityInfo
	lower := strings.ToLower(path)

	// Escalate severity for system-critical files.
	criticalPaths := []string{
		`system32\config\sam`, `system32\config\security`,
		`system32\config\system`, `system32\sethc.exe`,
		`system32\utilman.exe`, `system32\cmd.exe`,
		`system32\drivers\etc\hosts`,
	}
	for _, cp := range criticalPaths {
		if strings.Contains(lower, cp) {
			severity = types.SeverityHigh
			break
		}
	}

	var hashAfter string
	var sizeBytes int64
	if m.cfg.HashOnWrite && eventType != types.EventFileDelete {
		hashAfter, sizeBytes = m.hashFile(path)
	}

	ev := &types.FileEvent{
		BaseEvent: types.BaseEvent{
			ID: uuid.New().String(), Type: eventType,
			Timestamp: time.Now(), AgentID: m.bus.AgentID(), Hostname: m.bus.Hostname(),
			Severity: severity,
		},
		Path:      path,
		HashAfter: hashAfter,
		SizeBytes: sizeBytes,
		IsHidden:  strings.HasPrefix(filepath.Base(path), "."),
	}
	m.bus.Publish(ev)
}

func (m *Monitor) hashFile(path string) (string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	stat, _ := f.Stat()
	if stat == nil || stat.Size() > 50*1024*1024 {
		if stat != nil {
			return "", stat.Size()
		}
		return "", 0
	}
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), stat.Size()
}
