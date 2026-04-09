// Package fim monitors file integrity by computing SHA-256 checksums of
// critical system files and alerting when they differ from a stored baseline.
// Emits FIM_VIOLATION events for modifications, deletions, creations, and
// permission changes.

package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// fileRecord stores the baseline state for a single file.
type fileRecord struct {
	Hash    string      `json:"hash"`
	Size    int64       `json:"size"`
	Mode    os.FileMode `json:"mode"`
	ModTime time.Time   `json:"mod_time"`
}

// Config for the FIM monitor.
type Config struct {
	Enabled       bool
	PollIntervalS int
	WatchPaths    []string
	BaselinePath  string
	AutoBaseline  bool
}

// DefaultConfig returns sensible defaults for FIM.
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		PollIntervalS: 300,
		AutoBaseline:  true,
		BaselinePath:  "/var/lib/edr/fim_baseline.json",
		WatchPaths: []string{
			"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
			"/etc/sudoers", "/etc/sudoers.d",
			"/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
			"/etc/pam.d",
			"/etc/hosts", "/etc/resolv.conf",
			"/etc/ld.so.preload", "/etc/ld.so.conf",
			"/etc/crontab", "/etc/cron.d",
		},
	}
}

// Monitor polls file checksums and compares against a baseline.
type Monitor struct {
	cfg      Config
	bus      events.Bus
	log      zerolog.Logger
	stopCh   chan struct{}
	wg       sync.WaitGroup
	baseline map[string]fileRecord
	baseTime time.Time // when the baseline was created/loaded
}

// New creates a new FIM monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 300
	}
	if cfg.BaselinePath == "" {
		cfg.BaselinePath = "/var/lib/edr/fim_baseline.json"
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "fim").Logger(),
		stopCh: make(chan struct{}),
	}
}

// Start begins the FIM polling loop.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("FIM monitor disabled")
		return nil
	}

	// Load or create baseline.
	baseline, err := loadBaseline(m.cfg.BaselinePath)
	if err != nil {
		if !os.IsNotExist(err) {
			m.log.Warn().Err(err).Msg("failed to load FIM baseline")
		}
		if m.cfg.AutoBaseline {
			m.log.Info().Msg("creating initial FIM baseline")
			baseline = m.scanAll()
			if err := saveBaseline(m.cfg.BaselinePath, baseline); err != nil {
				m.log.Warn().Err(err).Msg("failed to save initial baseline")
			}
		} else {
			baseline = make(map[string]fileRecord)
		}
	}
	m.baseline = baseline
	m.baseTime = time.Now()
	m.log.Info().Int("files", len(baseline)).Strs("watch_paths", m.cfg.WatchPaths).Msg("FIM monitor baseline loaded")

	m.wg.Add(1)
	go m.pollLoop(ctx)
	return nil
}

// Stop terminates the FIM polling loop.
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
			m.check()
		}
	}
}

// check compares current file state against baseline.
func (m *Monitor) check() {
	current := m.scanAll()
	baseTimeStr := m.baseTime.Format(time.RFC3339)

	// Check for modified, permission-changed, and new files.
	for path, cur := range current {
		base, exists := m.baseline[path]
		if !exists {
			// New file not in baseline.
			m.emit(path, "", cur.Hash, cur.Size, cur.Mode, cur.ModTime, "created", baseTimeStr)
			continue
		}
		if cur.Hash != base.Hash {
			m.emit(path, base.Hash, cur.Hash, cur.Size, cur.Mode, cur.ModTime, "modified", baseTimeStr)
		} else if cur.Mode != base.Mode {
			m.emit(path, base.Hash, cur.Hash, cur.Size, cur.Mode, cur.ModTime, "permissions_changed", baseTimeStr)
		}
	}

	// Check for deleted files.
	for path, base := range m.baseline {
		if _, exists := current[path]; !exists {
			m.emit(path, base.Hash, "", 0, 0, time.Time{}, "deleted", baseTimeStr)
		}
	}
}

// scanAll walks all watch paths and computes file records.
func (m *Monitor) scanAll() map[string]fileRecord {
	result := make(map[string]fileRecord)
	for _, wp := range m.cfg.WatchPaths {
		info, err := os.Stat(wp)
		if err != nil {
			continue
		}
		if info.IsDir() {
			m.scanDir(wp, result)
		} else {
			if rec, err := m.scanFile(wp); err == nil {
				result[wp] = rec
			}
		}
	}
	return result
}

// scanDir recursively scans a directory.
func (m *Monitor) scanDir(dir string, result map[string]fileRecord) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			// Only recurse one level for safety.
			subEntries, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, sub := range subEntries {
				if !sub.IsDir() {
					subPath := filepath.Join(path, sub.Name())
					if rec, err := m.scanFile(subPath); err == nil {
						result[subPath] = rec
					}
				}
			}
		} else {
			if rec, err := m.scanFile(path); err == nil {
				result[path] = rec
			}
		}
	}
}

// scanFile computes the hash and metadata for a single file.
func (m *Monitor) scanFile(path string) (fileRecord, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileRecord{}, err
	}
	// Skip files larger than 50MB.
	if info.Size() > 50*1024*1024 {
		return fileRecord{}, fmt.Errorf("file too large: %d bytes", info.Size())
	}
	// Skip non-regular files.
	if !info.Mode().IsRegular() {
		return fileRecord{}, fmt.Errorf("not a regular file")
	}

	hash, err := hashFile(path)
	if err != nil {
		return fileRecord{}, err
	}

	return fileRecord{
		Hash:    hash,
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
	}, nil
}

// emit publishes a FIM_VIOLATION event.
func (m *Monitor) emit(filePath, expectedHash, actualHash string, size int64, mode os.FileMode, modTime time.Time, action, baselineTime string) {
	severity := types.SeverityMedium
	if action == "modified" || action == "deleted" {
		severity = types.SeverityHigh
	}
	// Critical paths get elevated severity.
	if strings.Contains(filePath, "shadow") || strings.Contains(filePath, "sudoers") ||
		strings.Contains(filePath, "sshd_config") || strings.Contains(filePath, "authorized_keys") {
		severity = types.SeverityCritical
	}

	modeStr := ""
	if mode != 0 {
		modeStr = fmt.Sprintf("%04o", mode.Perm())
	}
	modTimeStr := ""
	if !modTime.IsZero() {
		modTimeStr = modTime.Format(time.RFC3339)
	}

	m.bus.Publish(&types.FIMViolationEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventFIMViolation,
			Timestamp: time.Now(),
			Severity:  severity,
			Tags:      []string{"fim", action},
		},
		FilePath:     filePath,
		ExpectedHash: expectedHash,
		ActualHash:   actualHash,
		FileSize:     size,
		FileMode:     modeStr,
		ModTime:      modTimeStr,
		Action:       action,
		BaselineTime: baselineTime,
	})

	m.log.Warn().
		Str("path", filePath).
		Str("action", action).
		Str("expected", truncHash(expectedHash)).
		Str("actual", truncHash(actualHash)).
		Msg("FIM violation detected")
}

func truncHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

// ─── Baseline persistence ────────────────────────────────────────────────────

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadBaseline(path string) (map[string]fileRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline map[string]fileRecord
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return baseline, nil
}

func saveBaseline(path string, baseline map[string]fileRecord) error {
	// Ensure parent directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create baseline dir: %w", err)
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
