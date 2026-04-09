// Package cronmon watches cron directories and systemd timer files for changes.
// It subscribes to FILE_WRITE and FILE_CREATE events on the event bus, parses
// crontab content, and emits CRON_MODIFY events with structured data.

package cronmon

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config for the cron monitor.
type Config struct {
	Enabled    bool
	WatchPaths []string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		WatchPaths: []string{
			"/etc/crontab",
			"/etc/cron.d",
			"/etc/cron.daily",
			"/etc/cron.hourly",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			"/var/spool/cron",
		},
	}
}

// Monitor subscribes to file events and parses crontab/timer changes.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
	unsub  func() // unsubscribe from bus
}

// New creates a new cron monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = DefaultConfig().WatchPaths
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "cronmon").Logger(),
		stopCh: make(chan struct{}),
	}
}

// Start subscribes to file events on the bus and starts processing.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("cron monitor disabled")
		return nil
	}

	m.log.Info().
		Strs("watch_paths", m.cfg.WatchPaths).
		Msg("cron monitor starting")

	// Subscribe to FILE_WRITE events.
	unsubWrite := m.bus.Subscribe(string(types.EventFileWrite), func(ev events.Event) {
		m.handleFileEvent(ev, "modified")
	})

	// Subscribe to FILE_CREATE events.
	unsubCreate := m.bus.Subscribe(string(types.EventFileCreate), func(ev events.Event) {
		m.handleFileEvent(ev, "created")
	})

	// Subscribe to FILE_DELETE events.
	unsubDelete := m.bus.Subscribe(string(types.EventFileDelete), func(ev events.Event) {
		m.handleFileEvent(ev, "deleted")
	})

	m.unsub = func() {
		unsubWrite()
		unsubCreate()
		unsubDelete()
	}

	return nil
}

// Stop signals the monitor to shut down.
func (m *Monitor) Stop() {
	close(m.stopCh)
	if m.unsub != nil {
		m.unsub()
	}
	m.wg.Wait()
}

// handleFileEvent checks if a file event is cron-related and processes it.
func (m *Monitor) handleFileEvent(ev events.Event, action string) {
	// Extract the file path from the event.
	fileEv, ok := ev.(*types.FileEvent)
	if !ok {
		return
	}

	filePath := fileEv.Path
	if filePath == "" {
		return
	}

	if !m.isCronPath(filePath) {
		return
	}

	isTimer := isTimerFile(filePath)

	if action == "deleted" {
		// Emit a deletion event without parsing content.
		m.emitEvent(filePath, action, "", "", "", isTimer, false, nil)
		return
	}

	// Parse the file content.
	if isTimer {
		m.parseTimerFile(filePath, action)
	} else {
		m.parseCrontab(filePath, action)
	}
}

// isCronPath checks if a file path is under any of the watched cron directories.
func (m *Monitor) isCronPath(path string) bool {
	// Check systemd timer paths.
	if isTimerFile(path) {
		return true
	}

	for _, watchPath := range m.cfg.WatchPaths {
		if path == watchPath || strings.HasPrefix(path, watchPath+"/") {
			return true
		}
	}

	// Also check /var/spool/cron/crontabs/ which is the per-user crontab dir.
	if strings.HasPrefix(path, "/var/spool/cron/crontabs/") {
		return true
	}

	return false
}

// isTimerFile checks if a path is a systemd timer file.
func isTimerFile(path string) bool {
	return strings.HasSuffix(path, ".timer") &&
		(strings.HasPrefix(path, "/etc/systemd/system/") ||
			strings.HasPrefix(path, "/etc/systemd/user/"))
}

// parseCrontab reads a crontab file and emits events for each cron entry.
func (m *Monitor) parseCrontab(filePath, action string) {
	f, err := os.Open(filePath)
	if err != nil {
		m.log.Debug().Err(err).Str("path", filePath).Msg("cannot read crontab file")
		return
	}
	defer f.Close()

	// Determine the cron user from the file path.
	cronUser := inferCronUser(filePath)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip environment variable assignments (e.g., SHELL=/bin/bash).
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, "@") {
			// Check if it looks like a var assignment (no leading digit or *).
			if len(line) > 0 && line[0] != '/' && (line[0] < '0' || line[0] > '9') && line[0] != '*' && line[0] != '@' {
				continue
			}
		}

		schedule, user, command, ok := parseCronLine(line, cronUser)
		if !ok {
			continue
		}

		suspicious, tags := analyzeSuspicious(command)

		m.emitEvent(filePath, action, user, schedule, command, false, suspicious, tags)
	}
}

// parseCronLine parses a single crontab line into schedule, user, and command.
// Returns false if the line is not a valid cron entry.
func parseCronLine(line, defaultUser string) (schedule, user, command string, ok bool) {
	// Handle @reboot, @daily, etc.
	if strings.HasPrefix(line, "@") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", "", "", false
		}
		schedule = fields[0]
		// System crontabs (/etc/crontab, /etc/cron.d/*) have a user field.
		// Per-user crontabs (/var/spool/cron/crontabs/*) do not.
		rest := strings.Join(fields[1:], " ")
		return schedule, defaultUser, rest, true
	}

	// Standard 5-field schedule: min hour day month dow [user] command
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return "", "", "", false
	}

	// First 5 fields are the schedule.
	schedule = strings.Join(fields[0:5], " ")
	remaining := fields[5:]

	// If the file is a system crontab (/etc/crontab or /etc/cron.d/*),
	// the 6th field is the user. Otherwise it's part of the command.
	user = defaultUser
	command = strings.Join(remaining, " ")

	return schedule, user, command, true
}

// parseTimerFile reads a systemd .timer file and emits a CRON_MODIFY event.
func (m *Monitor) parseTimerFile(filePath, action string) {
	f, err := os.Open(filePath)
	if err != nil {
		m.log.Debug().Err(err).Str("path", filePath).Msg("cannot read timer file")
		return
	}
	defer f.Close()

	var schedule, command string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "OnCalendar=") {
			schedule = strings.TrimPrefix(line, "OnCalendar=")
		} else if strings.HasPrefix(line, "OnBootSec=") {
			schedule = strings.TrimPrefix(line, "OnBootSec=")
		} else if strings.HasPrefix(line, "OnUnitActiveSec=") {
			if schedule == "" {
				schedule = strings.TrimPrefix(line, "OnUnitActiveSec=")
			}
		} else if strings.HasPrefix(line, "ExecStart=") {
			command = strings.TrimPrefix(line, "ExecStart=")
		}
	}

	// If no ExecStart in the timer itself, derive it from the matching .service file.
	if command == "" {
		servicePath := strings.TrimSuffix(filePath, ".timer") + ".service"
		command = readExecStart(servicePath)
	}

	suspicious, tags := analyzeSuspicious(command)

	m.emitEvent(filePath, action, "root", schedule, command, true, suspicious, tags)
}

// readExecStart reads ExecStart from a systemd service file.
func readExecStart(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ExecStart=") {
			return strings.TrimPrefix(line, "ExecStart=")
		}
	}
	return ""
}

// inferCronUser determines the cron user from the file path.
func inferCronUser(filePath string) string {
	// Per-user crontabs: /var/spool/cron/crontabs/<username>
	if strings.HasPrefix(filePath, "/var/spool/cron/crontabs/") {
		return filepath.Base(filePath)
	}
	if strings.HasPrefix(filePath, "/var/spool/cron/") && !strings.Contains(filePath[len("/var/spool/cron/"):], "/") {
		return filepath.Base(filePath)
	}
	// System crontabs default to root.
	return "root"
}

// Patterns for suspicious command detection.
var (
	downloadPattern    = regexp.MustCompile(`\b(wget|curl|fetch)\b`)
	encodedPattern     = regexp.MustCompile(`\b(base64|eval)\b|\$\(|` + "`")
	reverseShellPattern = regexp.MustCompile(`/dev/tcp|nc\s+-e|bash\s+-i`)
	dropperPattern     = regexp.MustCompile(`chmod\s+\+x`)
)

// analyzeSuspicious checks a command for suspicious patterns.
func analyzeSuspicious(command string) (bool, []string) {
	if command == "" {
		return false, nil
	}

	var tags []string

	if downloadPattern.MatchString(command) {
		tags = append(tags, "downloads")
	}
	if encodedPattern.MatchString(command) {
		tags = append(tags, "encoded")
	}
	if reverseShellPattern.MatchString(command) {
		tags = append(tags, "reverse-shell")
	}
	if dropperPattern.MatchString(command) {
		tags = append(tags, "dropper")
	}

	return len(tags) > 0, tags
}

func (m *Monitor) emitEvent(filePath, action, cronUser, schedule, command string, isTimer, suspicious bool, tags []string) {
	severity := types.SeverityMedium
	if suspicious {
		severity = types.SeverityHigh
	}
	if action == "deleted" {
		severity = types.SeverityLow
	}

	ev := &types.CronModifyEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventCronModify,
			Timestamp: fileModTime(filePath),
			Severity:  severity,
			Tags:      tags,
		},
		FilePath:   filePath,
		Action:     action,
		CronUser:   cronUser,
		Schedule:   schedule,
		Command:    command,
		IsTimer:    isTimer,
		Suspicious: suspicious,
		CronTags:   tags,
	}

	m.log.Warn().
		Str("file", filePath).
		Str("action", action).
		Str("schedule", schedule).
		Bool("suspicious", suspicious).
		Msg("cron modification detected")

	m.bus.Publish(ev)
}

// fileModTime returns the modification time of a file, or now if it can't be read.
func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Now()
	}
	return info.ModTime()
}
