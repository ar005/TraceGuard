// internal/monitor/yarascan/monitor.go
//
// YARA scanner monitor — subscribes to FILE_CREATE/FILE_WRITE events from the
// event bus, reads executable files (identified by magic bytes or extension),
// and emits YARA_MATCH events when compiled rules match.
//
// Rules are pulled from the backend REST API on startup and refreshed every
// 10 minutes.  A YARA_MATCH event is treated by the backend detection engine
// exactly like a rule-fired alert: it creates an alert with the matched rule
// name and MITRE IDs.

package yarascan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	intyara "github.com/youredr/edr-agent/internal/yara"
	"github.com/youredr/edr-agent/pkg/types"
)


const (
	// maxScanBytes is the maximum number of bytes read from a file for scanning.
	maxScanBytes = 1 * 1024 * 1024 // 1 MB
	// ruleRefreshInterval is how often rules are re-fetched from the backend.
	ruleRefreshInterval = 10 * time.Minute
)

// execExtensions are file extensions that trigger a YARA scan.
var execExtensions = map[string]bool{
	".sh": true, ".py": true, ".pl": true, ".rb": true, ".js": true,
	".ps1": true, ".vbs": true, ".bat": true, ".cmd": true,
	".exe": true, ".dll": true, ".so": true, ".elf": true,
	".bin": true, ".deb": true, ".rpm": true, ".appimage": true,
	".jar": true, ".msi": true, ".hta": true,
}

// execMagics are byte-level file magic signatures that trigger a YARA scan.
var execMagics = [][]byte{
	{0x7F, 0x45, 0x4C, 0x46},             // ELF
	{0x4D, 0x5A},                          // MZ (PE/Windows)
	{0xCA, 0xFE, 0xBA, 0xBE},             // Mach-O fat
	{0xCE, 0xFA, 0xED, 0xFE},             // Mach-O 32-bit
	{0xCF, 0xFA, 0xED, 0xFE},             // Mach-O 64-bit
	{0x50, 0x4B, 0x03, 0x04},             // ZIP/JAR/APK
	{'#', '!'},                            // Shebang scripts
}

// Config configures the YARA scanner monitor.
type Config struct {
	Enabled        bool
	BackendURL     string // e.g. "http://localhost:8080"
	APIKey         string // optional; empty = no auth header
	WorkerCount    int
}

// Monitor subscribes to file events and runs YARA scans.
type Monitor struct {
	cfg     Config
	bus     events.Bus
	log     zerolog.Logger
	engine  *intyara.Engine
	mu      sync.RWMutex
	scanCh  chan scanRequest
}

type scanRequest struct {
	path      string
	eventID   string
	agentID   string
	hostname  string
	timestamp time.Time
}

// New creates a YARA scanner monitor. Call Start() to activate it.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "yarascan").Logger(),
		scanCh: make(chan scanRequest, 512),
	}
}

// Start begins rule fetching and subscribes to file events.
func (m *Monitor) Start(ctx context.Context) error {
	// Initial rule load.
	if err := m.refreshRules(ctx); err != nil {
		m.log.Warn().Err(err).Msg("initial YARA rule load failed — scanner will retry")
	}

	// Periodic rule refresh.
	go func() {
		t := time.NewTicker(ruleRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.refreshRules(ctx); err != nil {
					m.log.Warn().Err(err).Msg("YARA rule refresh failed")
				}
			}
		}
	}()

	// Subscribe to file events.
	unsub := m.bus.Subscribe("FILE_CREATE", func(ev events.Event) {
		fe, ok := ev.(*types.FileEvent)
		if !ok {
			return
		}
		if m.shouldScan(fe.Path) {
			select {
			case m.scanCh <- scanRequest{
				path:      fe.Path,
				eventID:   fe.ID,
				agentID:   m.bus.AgentID(),
				hostname:  m.bus.Hostname(),
				timestamp: fe.Timestamp,
			}:
			default:
				// Drop if queue full — scanner is saturated.
			}
		}
	})
	m.bus.Subscribe("FILE_WRITE", func(ev events.Event) {
		fe, ok := ev.(*types.FileEvent)
		if !ok {
			return
		}
		if m.shouldScan(fe.Path) {
			select {
			case m.scanCh <- scanRequest{
				path:      fe.Path,
				eventID:   fe.ID,
				agentID:   m.bus.AgentID(),
				hostname:  m.bus.Hostname(),
				timestamp: fe.Timestamp,
			}:
			default:
			}
		}
	})

	// Start scan workers.
	for i := 0; i < m.cfg.WorkerCount; i++ {
		go m.scanWorker(ctx)
	}

	<-ctx.Done()
	unsub()
	return nil
}

func (m *Monitor) scanWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-m.scanCh:
			m.scanFile(req)
		}
	}
}

func (m *Monitor) scanFile(req scanRequest) {
	m.mu.RLock()
	eng := m.engine
	m.mu.RUnlock()

	if eng == nil || eng.RuleCount() == 0 {
		return
	}

	f, err := os.Open(req.path)
	if err != nil {
		return // file may have been deleted already
	}
	data, err := io.ReadAll(io.LimitReader(f, maxScanBytes))
	f.Close()
	if err != nil || len(data) == 0 {
		return
	}

	matches := eng.ScanBytes(data)
	for _, m2 := range matches {
		m.emitMatch(req, m2)
	}
}

func (m *Monitor) emitMatch(req scanRequest, match intyara.MatchResult) {
	ev := &types.YARAMatchEvent{
		BaseEvent: types.BaseEvent{
			ID:        "yaramatch-" + uuid.New().String(),
			Type:      types.EventYARAMatch,
			AgentID:   req.agentID,
			Hostname:  req.hostname,
			Timestamp: req.timestamp,
		},
		YARARuleName:   match.RuleName,
		MatchedStrings: match.MatchedStrings,
		FilePath:       req.path,
		TriggerEventID: req.eventID,
	}
	m.bus.Publish(ev)
	m.log.Info().
		Str("rule", match.RuleName).
		Str("path", req.path).
		Strs("matched", match.MatchedStrings).
		Msg("YARA match")
}

// shouldScan returns true if the file path warrants a YARA scan.
func (m *Monitor) shouldScan(path string) bool {
	if path == "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if execExtensions[ext] {
		return true
	}
	// No extension — check magic bytes (read first 4 bytes without full open).
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	header := make([]byte, 4)
	n, _ := f.Read(header)
	f.Close()
	header = header[:n]
	for _, magic := range execMagics {
		if bytes.HasPrefix(header, magic) {
			return true
		}
	}
	return false
}

// ─── Rule fetching ────────────────────────────────────────────────────────────

type backendYARARule struct {
	ID       string `json:"id"`
	RuleText string `json:"rule_text"`
	Enabled  bool   `json:"enabled"`
}

func (m *Monitor) refreshRules(ctx context.Context) error {
	if m.cfg.BackendURL == "" {
		return nil
	}
	url := strings.TrimRight(m.cfg.BackendURL, "/") + "/api/v1/yara/rules/enabled"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if m.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.cfg.APIKey)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}

	var result struct {
		Rules []backendYARARule `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	texts := make([]string, 0, len(result.Rules))
	for _, r := range result.Rules {
		if r.Enabled && r.RuleText != "" {
			texts = append(texts, r.RuleText)
		}
	}

	eng, errs := intyara.New(texts)
	for _, e := range errs {
		m.log.Warn().Err(e).Msg("YARA rule compile error")
	}

	m.mu.Lock()
	m.engine = eng
	m.mu.Unlock()

	m.log.Info().Int("rules", eng.RuleCount()).Msg("YARA rules loaded")
	return nil
}
