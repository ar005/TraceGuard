// internal/monitor/pipe/monitor.go
// Named pipe monitor for Windows — enumerates \\.\pipe\* to detect new pipes.
//
// Polls using FindFirstFile/FindNextFile on the pipe namespace.
// Flags known C2 pipe patterns: msagent_*, MSSE-*-server, postex_*, status_*.

package pipe

import (
	"context"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// c2PipePatterns are named pipe prefixes/patterns used by known C2 frameworks.
var c2PipePatterns = []struct {
	Prefix string
	Tag    string
}{
	{"msagent_", "cobalt-strike"},
	{"MSSE-", "cobalt-strike"},
	{"postex_", "cobalt-strike"},
	{"status_", "cobalt-strike"},
	{"mojo.", "cobalt-strike"},
	{"win_svc", "cobalt-strike"},
	{"ntsvcs", "cobalt-strike"},
	{"scerpc", "cobalt-strike"},
	{"DserNamePipe", "cobalt-strike"},
	{"SearchTextHarvester", "cobalt-strike"},
	{"mypipe-f", "meterpreter"},
	{"mypipe-h", "meterpreter"},
	{"interprocess_", "sliver"},
	{"__winsvc_", "generic-c2"},
}

// Config for the pipe monitor.
type Config struct {
	PollIntervalS int
}

// Monitor polls named pipes and detects new ones.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a pipe monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 10
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "pipe").Logger(),
	}
}

// Start begins polling for named pipe changes.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("named pipe monitor started")
	return nil
}

// Stop halts the pipe monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("named pipe monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[string]bool)
	for _, name := range m.enumPipes() {
		known[name] = true
	}
	m.log.Debug().Int("baseline_pipes", len(known)).Msg("named pipe baseline captured")

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.enumPipes()
			currentMap := make(map[string]bool)

			for _, name := range current {
				currentMap[name] = true
				if !known[name] {
					m.emitPipeCreate(name)
				}
			}

			known = currentMap
		}
	}
}

// enumPipes lists all named pipes using FindFirstFile/FindNextFile on \\.\pipe\*.
func (m *Monitor) enumPipes() []string {
	searchPath, err := windows.UTF16PtrFromString(`\\.\pipe\*`)
	if err != nil {
		return nil
	}

	var fd windows.Win32finddata
	handle, err := windows.FindFirstFile(searchPath, &fd)
	if err != nil {
		return nil
	}
	defer windows.FindClose(handle)

	var pipes []string
	for {
		name := windows.UTF16ToString(fd.FileName[:])
		if name != "" && name != "." && name != ".." {
			pipes = append(pipes, name)
		}

		err = windows.FindNextFile(handle, &fd)
		if err != nil {
			break
		}
	}

	return pipes
}

func (m *Monitor) emitPipeCreate(name string) {
	severity := types.SeverityInfo
	var tags []string
	tags = append(tags, "named-pipe")

	// Check against C2 patterns.
	lowerName := strings.ToLower(name)
	for _, pattern := range c2PipePatterns {
		if strings.HasPrefix(lowerName, strings.ToLower(pattern.Prefix)) {
			severity = types.SeverityCritical
			tags = append(tags, "c2-pipe", pattern.Tag)
			break
		}
	}

	ev := &types.PipeEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventPipeCreate,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      tags,
		},
		PipePath: `\\.\pipe\` + name,
		Location: "local",
	}

	m.bus.Publish(ev)

	if severity >= types.SeverityHigh {
		m.log.Warn().Str("pipe", name).Strs("tags", tags).Msg("suspicious named pipe detected")
	} else {
		m.log.Debug().Str("pipe", name).Msg("new named pipe")
	}
}

// Ensure we use unsafe to prevent "imported and not used" for the pipe enumeration.
var _ = unsafe.Sizeof(0)

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
