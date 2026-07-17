//go:build windows

// internal/monitor/winevent/monitor.go
// Generic Windows Event Log monitor — real-time push delivery via EvtSubscribe.
//
// Primary path: one EvtSubscribe push subscription per configured channel,
// with an XPath filter derived from the channel's EventID list. Events arrive
// in real time with no polling lag via wevtapi.dll!EvtSubscribe.
//
// Fallback: if all EvtSubscribe calls fail (insufficient privilege or old OS),
// degrades to the original wevtutil polling approach with the configured
// poll interval and per-channel time-windowed XPath queries.

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

	"github.com/youredr/edr-agent-win/internal/etw"
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
	PollIntervalS    int             `mapstructure:"poll_interval_s"`
	Channels         []ChannelConfig `mapstructure:"channels"`
	MaxEventsPerPoll int             `mapstructure:"max_events_per_poll"`
}

// Monitor watches Windows Event Log channels for events.
type Monitor struct {
	cfg     Config
	bus     events.Bus
	log     zerolog.Logger
	closers []func()
	cancel  context.CancelFunc
	wg      sync.WaitGroup
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

// Start creates one EvtSubscribe push subscription per configured channel.
// Falls back to wevtutil polling only when ALL channel subscriptions fail.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	var failedChannels []string
	for _, ch := range m.cfg.Channels {
		query := xpathForIDs(ch.EventIDs)
		chName := ch.Name
		closer, err := etw.NewLogSubscription(ctx, chName, query, func(xmlStr string) {
			m.handleXML(chName, xmlStr)
		})
		if err != nil {
			m.log.Warn().Err(err).Str("channel", chName).Msg("EvtSubscribe failed for channel")
			failedChannels = append(failedChannels, chName)
			continue
		}
		m.closers = append(m.closers, closer)
	}

	if len(m.closers) == 0 {
		m.log.Warn().
			Strs("channels", failedChannels).
			Msg("all EvtSubscribe calls failed, falling back to polling")
		return m.startPolling(ctx)
	}

	m.log.Info().
		Int("subscribed", len(m.closers)).
		Int("failed", len(failedChannels)).
		Msg("winevent monitor started (EvtSubscribe)")
	return nil
}

// Stop cancels all subscriptions (or polling context) and waits for goroutines.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	for _, c := range m.closers {
		c()
	}
	m.wg.Wait()
	m.log.Info().Msg("winevent monitor stopped")
}

// handleXML parses a single event XML string delivered by EvtSubscribe and
// dispatches it to processEvent. Called from the etw dispatch goroutine.
func (m *Monitor) handleXML(channel, xmlStr string) {
	var evt evtEvent
	if err := xml.Unmarshal([]byte(xmlStr), &evt); err != nil {
		m.log.Debug().Err(err).Str("channel", channel).Msg("failed to parse event XML")
		return
	}
	m.processEvent(channel, evt)
}

// xpathForIDs builds an XPath query for EvtSubscribe.
// No time filter is needed — EvtSubscribe with evtSubscribeToFutureEvents
// delivers only events from the subscription point onward.
func xpathForIDs(eventIDs []int) string {
	if len(eventIDs) == 0 {
		return "*"
	}
	parts := make([]string, 0, len(eventIDs))
	for _, id := range eventIDs {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	return fmt.Sprintf("*[System[(%s)]]", strings.Join(parts, " or "))
}

// XML structures for Windows Event Log events.
// Compatible with both EvtRender (EvtSubscribe) and wevtutil XML output.
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

// ── Polling fallback ──────────────────────────────────────────────────────────
// Preserved from original implementation; activated when all EvtSubscribe calls fail.

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().
		Int("channels", len(m.cfg.Channels)).
		Int("poll_interval_s", m.cfg.PollIntervalS).
		Msg("winevent monitor started (polling Windows Event Log)")
	return nil
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

	query := m.buildXPathQuery(ch.EventIDs, since)

	cmd := exec.CommandContext(cmdCtx, "wevtutil", "qe", ch.Name,
		"/q:"+query,
		fmt.Sprintf("/c:%d", m.cfg.MaxEventsPerPoll),
		"/rd:true",
		"/f:xml",
	)
	out, err := cmd.Output()
	if err != nil {
		m.log.Debug().Err(err).Str("channel", ch.Name).Msg("wevtutil query returned error (may be empty)")
		return nil
	}

	if len(out) == 0 {
		return nil
	}

	wrapped := "<Events>" + string(out) + "</Events>"

	var parsed evtEvents
	if err := xml.Unmarshal([]byte(wrapped), &parsed); err != nil {
		m.log.Debug().Err(err).Str("channel", ch.Name).Msg("failed to parse wevtutil XML output")
		return nil
	}

	return parsed.Events
}

// buildXPathQuery constructs a time-windowed XPath filter for wevtutil polling.
func (m *Monitor) buildXPathQuery(eventIDs []int, since time.Time) string {
	timePart := fmt.Sprintf("TimeCreated[@SystemTime>='%s']",
		since.UTC().Format("2006-01-02T15:04:05.000Z"))

	if len(eventIDs) == 0 {
		return fmt.Sprintf("*[System[%s]]", timePart)
	}

	var parts []string
	for _, id := range eventIDs {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	return fmt.Sprintf("*[System[(%s) and %s]]", strings.Join(parts, " or "), timePart)
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
