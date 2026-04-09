// internal/monitor/fim/monitor.go
// File Integrity Monitoring for Windows — SHA-256 baseline comparison.
//
// Maintains a JSON baseline of watched files (hash, size, permissions, mod time).
// Periodically polls watched paths and detects modified, deleted, and new files.
// Emits FIM_VIOLATION events.
//
// Default watched paths: hosts, SAM, SECURITY, SYSTEM, sethc.exe, utilman.exe,
// GroupPolicy, Tasks.

package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// Default watched paths for Windows.
var defaultWatchPaths = []string{
	`C:\Windows\System32\drivers\etc\hosts`,
	`C:\Windows\System32\config\SAM`,
	`C:\Windows\System32\config\SECURITY`,
	`C:\Windows\System32\config\SYSTEM`,
	`C:\Windows\System32\sethc.exe`,
	`C:\Windows\System32\utilman.exe`,
	`C:\Windows\System32\cmd.exe`,
	`C:\Windows\System32\osk.exe`,
	`C:\Windows\System32\GroupPolicy`,
	`C:\Windows\Tasks`,
}

// Config for the FIM monitor.
type Config struct {
	PollIntervalS int
	WatchPaths    []string
	BaselinePath  string
	AutoBaseline  bool
}

// Monitor performs file integrity monitoring.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a FIM monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 300
	}
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = defaultWatchPaths
	}
	if cfg.BaselinePath == "" {
		cfg.BaselinePath = `C:\ProgramData\TraceGuard\fim_baseline.json`
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "fim").Logger(),
	}
}

// fileEntry represents a file in the baseline.
type fileEntry struct {
	Path    string `json:"path"`
	Hash    string `json:"hash"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
}

// baseline is the full baseline state.
type baseline struct {
	CreatedAt string               `json:"created_at"`
	Files     map[string]fileEntry `json:"files"`
}

// Start begins the FIM polling loop.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Int("watch_paths", len(m.cfg.WatchPaths)).Msg("FIM monitor started")
	return nil
}

// Stop halts the FIM monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("FIM monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Load or create baseline.
	bl := m.loadBaseline()
	if bl == nil || len(bl.Files) == 0 {
		if m.cfg.AutoBaseline {
			m.log.Info().Msg("creating initial FIM baseline")
			bl = m.createBaseline()
			m.saveBaseline(bl)
		} else {
			m.log.Warn().Msg("no FIM baseline found and auto_baseline=false; skipping")
			return
		}
	}

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkIntegrity(bl)
		}
	}
}

func (m *Monitor) loadBaseline() *baseline {
	data, err := os.ReadFile(m.cfg.BaselinePath)
	if err != nil {
		return nil
	}
	var bl baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		m.log.Error().Err(err).Msg("corrupt FIM baseline")
		return nil
	}
	m.log.Info().Int("files", len(bl.Files)).Msg("FIM baseline loaded")
	return &bl
}

func (m *Monitor) saveBaseline(bl *baseline) {
	// Ensure directory exists.
	dir := filepath.Dir(m.cfg.BaselinePath)
	os.MkdirAll(dir, 0750)

	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		m.log.Error().Err(err).Msg("marshal FIM baseline")
		return
	}
	if err := os.WriteFile(m.cfg.BaselinePath, data, 0640); err != nil {
		m.log.Error().Err(err).Msg("write FIM baseline")
	}
}

func (m *Monitor) createBaseline() *baseline {
	bl := &baseline{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Files:     make(map[string]fileEntry),
	}

	for _, path := range m.cfg.WatchPaths {
		m.walkPath(path, func(filePath string, info os.FileInfo) {
			hash := hashFile(filePath)
			bl.Files[filePath] = fileEntry{
				Path:    filePath,
				Hash:    hash,
				Size:    info.Size(),
				Mode:    info.Mode().String(),
				ModTime: info.ModTime().UTC().Format(time.RFC3339),
			}
		})
	}

	m.log.Info().Int("files", len(bl.Files)).Msg("FIM baseline created")
	return bl
}

func (m *Monitor) checkIntegrity(bl *baseline) {
	// Gather current state.
	currentFiles := make(map[string]fileEntry)
	for _, path := range m.cfg.WatchPaths {
		m.walkPath(path, func(filePath string, info os.FileInfo) {
			hash := hashFile(filePath)
			currentFiles[filePath] = fileEntry{
				Path:    filePath,
				Hash:    hash,
				Size:    info.Size(),
				Mode:    info.Mode().String(),
				ModTime: info.ModTime().UTC().Format(time.RFC3339),
			}
		})
	}

	// Check for modified files.
	for path, expected := range bl.Files {
		actual, exists := currentFiles[path]
		if !exists {
			m.emitViolation(expected, fileEntry{}, "deleted")
			continue
		}
		if actual.Hash != expected.Hash {
			m.emitViolation(expected, actual, "modified")
		}
	}

	// Check for new files.
	for path, actual := range currentFiles {
		if _, exists := bl.Files[path]; !exists {
			m.emitViolation(fileEntry{}, actual, "created")
		}
	}
}

func (m *Monitor) emitViolation(expected, actual fileEntry, action string) {
	severity := types.SeverityHigh
	if action == "created" {
		severity = types.SeverityMedium
	}

	filePath := expected.Path
	if filePath == "" {
		filePath = actual.Path
	}

	ev := &types.FIMViolationEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventFIMViolation,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      []string{"fim", action},
		},
		FilePath:     filePath,
		ExpectedHash: expected.Hash,
		ActualHash:   actual.Hash,
		FileSize:     actual.Size,
		FileMode:     actual.Mode,
		ModTime:      actual.ModTime,
		Action:       action,
		BaselineTime: expected.ModTime,
	}

	m.bus.Publish(ev)
	m.log.Warn().
		Str("file", filePath).
		Str("action", action).
		Str("expected_hash", truncate(expected.Hash, 16)).
		Str("actual_hash", truncate(actual.Hash, 16)).
		Msg("FIM violation")
}

// walkPath walks a path (file or directory) and calls fn for each regular file.
func (m *Monitor) walkPath(path string, fn func(string, os.FileInfo)) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if !info.IsDir() {
		fn(path, info)
		return
	}

	// Walk directory, limit depth to 2.
	filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			rel, _ := filepath.Rel(path, p)
			if rel != "." {
				depth := len(filepath.SplitList(rel))
				if depth > 2 {
					return filepath.SkipDir
				}
			}
			return nil
		}
		fn(p, fi)
		return nil
	})
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.Size() > 100*1024*1024 {
		return ""
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
