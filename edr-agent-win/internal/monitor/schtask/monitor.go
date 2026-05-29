// internal/monitor/schtask/monitor.go
// Scheduled task monitor for Windows — polls `schtasks /query /fo CSV /v`.
//
// Detects new or modified scheduled tasks compared to a baseline.
// Flags suspicious patterns: encoded commands, download URLs, AppData paths.
// Emits CRON_MODIFY events (same type as Linux cron monitor).

package schtask

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// suspiciousIndicators are patterns in task actions that warrant elevated severity.
var suspiciousIndicators = []struct {
	Pattern string
	Tag     string
}{
	{"-enc ", "encoded-command"},
	{"-encodedcommand", "encoded-command"},
	{"powershell", "powershell"},
	{"downloadstring", "download"},
	{"downloadfile", "download"},
	{"invoke-webrequest", "web-request"},
	{"http://", "url"},
	{"https://", "url"},
	{"certutil", "certutil"},
	{"bitsadmin", "bitsadmin"},
	{`\appdata\`, "appdata-path"},
	{`\temp\`, "temp-path"},
	{`\programdata\`, "programdata-path"},
	{"cmd /c", "cmd-exec"},
	{"cmd.exe /c", "cmd-exec"},
	{"wscript", "script-host"},
	{"cscript", "script-host"},
	{"mshta", "mshta"},
	{"regsvr32", "regsvr32"},
}

// Config for the scheduled task monitor.
type Config struct {
	PollIntervalS int
}

// Monitor polls scheduled tasks and detects changes.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a scheduled task monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 30
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "schtask").Logger(),
	}
}

// taskInfo holds parsed scheduled task details.
type taskInfo struct {
	Name      string
	NextRun   string
	Status    string
	TaskToRun string
	RunAsUser string
	Schedule  string
	LastRun   string
}

// Start begins polling for scheduled task changes.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("scheduled task monitor started")
	return nil
}

// Stop halts the scheduled task monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("scheduled task monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Build initial baseline.
	known := make(map[string]taskInfo)
	for _, t := range m.enumTasks(ctx) {
		known[t.Name] = t
	}
	m.log.Debug().Int("baseline_tasks", len(known)).Msg("scheduled task baseline captured")

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.enumTasks(ctx)
			currentMap := make(map[string]taskInfo)

			for _, t := range current {
				currentMap[t.Name] = t
				prev, exists := known[t.Name]
				if !exists {
					m.emitTaskChange(t, "created")
				} else if prev.TaskToRun != t.TaskToRun || prev.Schedule != t.Schedule {
					m.emitTaskChange(t, "modified")
				}
			}

			for name, t := range known {
				if _, exists := currentMap[name]; !exists {
					m.emitTaskChange(t, "deleted")
				}
			}

			known = currentMap
		}
	}
}

func (m *Monitor) enumTasks(ctx context.Context) []taskInfo {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "schtasks", "/query", "/fo", "CSV", "/v")
	out, err := cmd.Output()
	if err != nil {
		m.log.Debug().Err(err).Msg("schtasks query failed")
		return nil
	}

	return parseSchTasksCSV(out)
}

// parseSchTasksCSV parses schtasks /fo CSV /v output.
// Columns vary by locale but typically include: HostName, TaskName, Next Run Time,
// Status, Logon Mode, Last Run Time, Last Result, Author, Task To Run,
// Start In, Comment, Scheduled Task State, Idle Time, Power Management,
// Run As User, Delete Task If Not Rescheduled, Stop Task If Runs X Hours and X Mins,
// Schedule, Schedule Type, Start Time, Start Date, End Date, Days, Months, Repeat: Every,
// Repeat: Until: Time, Repeat: Until: Duration, Repeat: Stop If Still Running
func parseSchTasksCSV(data []byte) []taskInfo {
	var tasks []taskInfo

	reader := csv.NewReader(bufio.NewReader(bytes.NewReader(data)))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // variable fields

	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}

	// Build column index from header.
	header := records[0]
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[strings.TrimSpace(strings.ToLower(h))] = i
	}

	getCol := func(row []string, name string) string {
		if idx, ok := colIdx[name]; ok && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		return ""
	}

	for _, row := range records[1:] {
		taskName := getCol(row, "taskname")
		if taskName == "" {
			continue
		}
		// Skip Microsoft system tasks.
		if strings.HasPrefix(taskName, `\Microsoft\`) {
			continue
		}

		tasks = append(tasks, taskInfo{
			Name:      taskName,
			NextRun:   getCol(row, "next run time"),
			Status:    getCol(row, "status"),
			TaskToRun: getCol(row, "task to run"),
			RunAsUser: getCol(row, "run as user"),
			Schedule:  getCol(row, "schedule type"),
			LastRun:   getCol(row, "last run time"),
		})
	}

	return tasks
}

func (m *Monitor) emitTaskChange(t taskInfo, action string) {
	severity := types.SeverityMedium
	suspicious := false
	var tags []string
	tags = append(tags, "scheduled-task", action)

	// Check for suspicious indicators.
	lowerAction := strings.ToLower(t.TaskToRun)
	for _, ind := range suspiciousIndicators {
		if strings.Contains(lowerAction, ind.Pattern) {
			suspicious = true
			severity = types.SeverityHigh
			tags = append(tags, ind.Tag)
		}
	}

	ev := &types.CronModifyEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventCronModify,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      tags,
		},
		FilePath:   t.Name,
		Action:     action,
		CronUser:   t.RunAsUser,
		Schedule:   t.Schedule,
		Command:    t.TaskToRun,
		Suspicious: suspicious,
	}

	m.bus.Publish(ev)

	if suspicious {
		m.log.Warn().Str("task", t.Name).Str("action", action).Str("command", t.TaskToRun).Msg("suspicious scheduled task")
	} else {
		m.log.Info().Str("task", t.Name).Str("action", action).Msg("scheduled task change")
	}
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
