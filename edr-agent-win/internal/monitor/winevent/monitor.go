// internal/monitor/winevent/monitor.go
// Generic Windows Event Log monitor — ingests events from configurable channels
// using wevtutil. Supports arbitrary channels and event ID filters.
//
// Unlike the auth monitor which is limited to Security 4624/4625/4648, this
// monitor provides broad visibility across Security, System, Application,
// Sysmon, and any custom channels.

package winevent

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// ChannelConfig defines a single event log channel to monitor.
type ChannelConfig struct {
	Name     string `mapstructure:"name"`
	EventIDs []int  `mapstructure:"event_ids"`
}

// Config for the winevent monitor.
type Config struct {
	PollIntervalS   int             `mapstructure:"poll_interval_s"`
	Channels        []ChannelConfig `mapstructure:"channels"`
	MaxEventsPerPoll int            `mapstructure:"max_events_per_poll"`
}

// Monitor polls Windows Event Logs for events across configured channels.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a winevent monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 15
	}
	if cfg.MaxEventsPerPoll <= 0 {
		cfg.MaxEventsPerPoll = 100
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "winevent").Logger(),
	}
}

// Start begins polling configured event log channels.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().
		Int("channels", len(m.cfg.Channels)).
		Int("poll_interval_s", m.cfg.PollIntervalS).
		Msg("winevent monitor started (polling Windows Event Log)")
	return nil
}

// Stop halts the winevent monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("winevent monitor stopped")
}

// XML structures for wevtutil output.
type evtEvents struct {
	Events []evtEvent `xml:"Event"`
}

type evtEvent struct {
	System evtSystem `xml:"System"`
	Data   []evtData `xml:"EventData>Data"`
}

type evtSystem struct {
	Provider    evtProvider `xml:"Provider"`
	EventID     int         `xml:"EventID"`
	Level       int         `xml:"Level"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
}

type evtProvider struct {
	Name string `xml:"Name,attr"`
}

type evtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Track last seen event time per channel to avoid duplicates.
	lastSeen := make(map[string]time.Time)
	for _, ch := range m.cfg.Channels {
		lastSeen[ch.Name] = time.Now()
	}

	// Initial delay to let the system settle.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, ch := range m.cfg.Channels {
				since := lastSeen[ch.Name]
				evts := m.queryChannel(ctx, ch, since)
				for _, evt := range evts {
					m.processEvent(ch.Name, evt)
				}
				lastSeen[ch.Name] = time.Now()
			}
		}
	}
}

func (m *Monitor) queryChannel(ctx context.Context, ch ChannelConfig, since time.Time) []evtEvent {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Build XPath filter.
	query := m.buildXPathQuery(ch.EventIDs, since)

	cmd := exec.CommandContext(cmdCtx, "wevtutil", "qe", ch.Name,
		"/q:"+query,
		fmt.Sprintf("/c:%d", m.cfg.MaxEventsPerPoll),
		"/rd:true",
		"/f:xml",
	)
	out, err := cmd.Output()
	if err != nil {
		// wevtutil often returns error if no events match — that is fine.
		m.log.Debug().Err(err).Str("channel", ch.Name).Msg("wevtutil query returned error (may be empty)")
		return nil
	}

	if len(out) == 0 {
		return nil
	}

	// wevtutil outputs individual <Event> elements, not a wrapping root.
	// Wrap them in a root element for valid XML parsing.
	wrapped := "<Events>" + string(out) + "</Events>"

	var parsed evtEvents
	if err := xml.Unmarshal([]byte(wrapped), &parsed); err != nil {
		m.log.Debug().Err(err).Str("channel", ch.Name).Msg("failed to parse wevtutil XML output")
		return nil
	}

	return parsed.Events
}

// buildXPathQuery constructs an XPath filter for wevtutil.
func (m *Monitor) buildXPathQuery(eventIDs []int, since time.Time) string {
	timePart := fmt.Sprintf("TimeCreated[@SystemTime>='%s']",
		since.UTC().Format("2006-01-02T15:04:05.000Z"))

	if len(eventIDs) == 0 {
		// All events from the channel since the given time.
		return fmt.Sprintf("*[System[%s]]", timePart)
	}

	// Build EventID filter: (EventID=X or EventID=Y or ...)
	var parts []string
	for _, id := range eventIDs {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	eventFilter := strings.Join(parts, " or ")

	return fmt.Sprintf("*[System[(%s) and %s]]", eventFilter, timePart)
}

func (m *Monitor) processEvent(channel string, evt evtEvent) {
	dataMap := make(map[string]string)
	for _, d := range evt.Data {
		if d.Name != "" {
			dataMap[d.Name] = d.Value
		}
	}

	severity := m.mapLevel(evt.System.Level)

	ev := &types.WinEventLogEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventWinEvent,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      []string{"winevent", channel, fmt.Sprintf("event-%d", evt.System.EventID)},
		},
		Channel:     channel,
		WinEventID:  evt.System.EventID,
		Level:       evt.System.Level,
		LevelName:   levelName(evt.System.Level),
		Provider:    evt.System.Provider.Name,
		Computer:    evt.System.Computer,
		TimeCreated: evt.System.TimeCreated.SystemTime,
		EventData:   dataMap,
	}

	m.bus.Publish(ev)
	m.log.Debug().
		Str("channel", channel).
		Int("event_id", evt.System.EventID).
		Str("provider", evt.System.Provider.Name).
		Int("level", evt.System.Level).
		Msg("winevent")
}

// mapLevel converts Windows Event Log level to TraceGuard severity.
// Level values: 1=Critical, 2=Error, 3=Warning, 4=Informational, 0=LogAlways(Info)
func (m *Monitor) mapLevel(level int) types.Severity {
	switch level {
	case 1:
		return types.SeverityCritical
	case 2:
		return types.SeverityHigh
	case 3:
		return types.SeverityMedium
	case 4:
		return types.SeverityLow
	case 0:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// levelName returns a human-readable name for the Windows event level.
func levelName(level int) string {
	switch level {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	case 0:
		return "LogAlways"
	default:
		return strconv.Itoa(level)
	}
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
