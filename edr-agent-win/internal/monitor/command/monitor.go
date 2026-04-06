// internal/monitor/command/monitor.go
// Command monitor for Windows — detects suspicious PowerShell and cmd.exe activity.
//
// Polls PowerShell ConsoleHost_history.txt for new entries and flags commands
// containing known-malicious patterns: -enc, IEX, Invoke-Expression,
// DownloadString, Start-Process, certutil, etc.

package command

import (
	"bufio"
	"context"
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

// Suspicious command patterns — case-insensitive matching.
var suspiciousPatterns = []struct {
	Pattern  string
	Severity types.Severity
	Tag      string
}{
	{"-encodedcommand", types.SeverityHigh, "encoded-command"},
	{"-enc ", types.SeverityHigh, "encoded-command"},
	{"iex(", types.SeverityHigh, "iex"},
	{"iex (", types.SeverityHigh, "iex"},
	{"invoke-expression", types.SeverityHigh, "invoke-expression"},
	{"downloadstring", types.SeverityHigh, "download"},
	{"downloadfile", types.SeverityHigh, "download"},
	{"invoke-webrequest", types.SeverityMedium, "web-request"},
	{"start-process", types.SeverityLow, "start-process"},
	{"certutil", types.SeverityMedium, "certutil"},
	{"bitsadmin", types.SeverityMedium, "bitsadmin"},
	{"net user ", types.SeverityMedium, "user-mgmt"},
	{"net localgroup", types.SeverityMedium, "group-mgmt"},
	{"reg add", types.SeverityMedium, "reg-modify"},
	{"sc create", types.SeverityMedium, "service-create"},
	{"schtasks /create", types.SeverityMedium, "schtask-create"},
	{"mimikatz", types.SeverityCritical, "mimikatz"},
	{"invoke-mimikatz", types.SeverityCritical, "mimikatz"},
	{"sekurlsa", types.SeverityCritical, "credential-dump"},
	{"-noprofile", types.SeverityLow, "noprofile"},
	{"-windowstyle hidden", types.SeverityMedium, "hidden-window"},
	{"bypass", types.SeverityLow, "exec-bypass"},
	{"new-object net.webclient", types.SeverityHigh, "webclient"},
	{"[convert]::frombase64", types.SeverityHigh, "base64-decode"},
}

// Config for the command monitor.
type Config struct{}

// Monitor polls PowerShell history files for suspicious commands.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a command monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "command").Logger(),
	}
}

// Start begins polling PowerShell history files.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("command monitor started (polling PowerShell history)")
	return nil
}

// Stop halts the command monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("command monitor stopped")
}

// historyState tracks how far we have read into a history file.
type historyState struct {
	LineCount int
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Track per-file read progress.
	state := make(map[string]*historyState)

	// Initial baseline — read existing lines without alerting.
	for _, path := range m.findHistoryFiles() {
		lines := m.readHistory(path)
		state[path] = &historyState{LineCount: len(lines)}
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, path := range m.findHistoryFiles() {
				lines := m.readHistory(path)
				prev, exists := state[path]
				if !exists {
					prev = &historyState{LineCount: 0}
					state[path] = prev
				}

				// Process only new lines.
				if len(lines) > prev.LineCount {
					for _, line := range lines[prev.LineCount:] {
						m.analyzeLine(line, path)
					}
					prev.LineCount = len(lines)
				}
			}
		}
	}
}

// findHistoryFiles locates all PSReadLine history files on the system.
func (m *Monitor) findHistoryFiles() []string {
	var paths []string

	// Check all user profiles.
	usersDir := `C:\Users`
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return paths
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "." || name == ".." || name == "Public" || name == "Default" || name == "Default User" || name == "All Users" {
			continue
		}
		histPath := filepath.Join(usersDir, name,
			"AppData", "Roaming", "Microsoft", "Windows", "PowerShell",
			"PSReadLine", "ConsoleHost_history.txt")
		if _, err := os.Stat(histPath); err == nil {
			paths = append(paths, histPath)
		}
	}

	return paths
}

// readHistory reads all lines from a history file.
func (m *Monitor) readHistory(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// analyzeLine checks a command line against suspicious patterns.
func (m *Monitor) analyzeLine(line, historyFile string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	lower := strings.ToLower(line)

	var matchedTags []string
	maxSeverity := types.SeverityInfo

	for _, sp := range suspiciousPatterns {
		if strings.Contains(lower, sp.Pattern) {
			matchedTags = append(matchedTags, sp.Tag)
			if sp.Severity > maxSeverity {
				maxSeverity = sp.Severity
			}
		}
	}

	// Only emit if something suspicious was found.
	if len(matchedTags) == 0 {
		return
	}

	tags := append([]string{"powershell", "command"}, matchedTags...)

	// Extract username from history file path.
	username := extractUserFromPath(historyFile)

	ev := &types.BaseEvent{
		ID:        uuid.New().String(),
		Type:      types.EventCmdExec,
		Timestamp: time.Now(),
		AgentID:   m.bus.AgentID(),
		Hostname:  m.bus.Hostname(),
		Severity:  maxSeverity,
		Tags:      tags,
		Process: types.ProcessContext{
			Username: username,
			Comm:     "powershell.exe",
			Cmdline:  line,
		},
	}

	m.bus.Publish(ev)
	m.log.Warn().
		Str("command", truncate(line, 200)).
		Strs("tags", matchedTags).
		Str("severity", maxSeverity.String()).
		Msg("suspicious command detected")
}

func extractUserFromPath(path string) string {
	// Path: C:\Users\<username>\AppData\...
	parts := strings.Split(path, `\`)
	for i, p := range parts {
		if strings.EqualFold(p, "Users") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
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
