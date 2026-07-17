//go:build windows

// internal/monitor/auth/monitor.go
// Authentication monitor for Windows.
//
// Primary path: EvtSubscribe push delivery to the Security channel with an
// XPath filter for logon/logoff events 4624, 4625, 4634, and 4648.  Events
// arrive in real time (<1 ms vs 10-second polling) via wevtapi.dll!EvtSubscribe.
//
// Fallback: if EvtSubscribe fails (insufficient privilege or Windows Server
// 2012 R2), degrades to the original 10-second wevtutil polling approach.

package auth

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/etw"
	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// Config for the auth monitor.
type Config struct{}

// Monitor watches the Security Event Log for authentication events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	closer func()
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates an auth monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "auth").Logger(),
	}
}

// authXPathQuery is the EvtSubscribe XPath filter for the Security channel.
// 4624=LogonSuccess, 4625=LogonFailed, 4634=Logoff, 4648=ExplicitCredentials.
const authXPathQuery = `*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648)]]`

// Start subscribes to the Security Event Log via EvtSubscribe for real-time
// event delivery. Falls back to 10-second wevtutil polling if EvtSubscribe fails.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	closer, err := etw.NewLogSubscription(ctx, "Security", authXPathQuery, m.handleXML)
	if err != nil {
		m.log.Warn().Err(err).Msg("EvtSubscribe unavailable, falling back to polling")
		return m.startPolling(ctx)
	}
	m.closer = closer
	m.log.Info().Msg("auth monitor started (EvtSubscribe Security channel)")
	return nil
}

// Stop cancels the subscription (or polling context) and waits for goroutines.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.closer != nil {
		m.closer()
	}
	m.wg.Wait()
	m.log.Info().Msg("auth monitor stopped")
}

// handleXML parses a single Security event XML string delivered by EvtSubscribe
// and dispatches it to processEvent. Called from the etw dispatch goroutine.
func (m *Monitor) handleXML(xmlStr string) {
	var evt evtEvent
	if err := xml.Unmarshal([]byte(xmlStr), &evt); err != nil {
		m.log.Debug().Err(err).Msg("failed to parse event XML")
		return
	}
	m.processEvent(evt)
}

// XML structures for Security Event Log events.
// Compatible with both EvtRender (EvtSubscribe) and wevtutil XML output.
type evtEvents struct {
	Events []evtEvent `xml:"Event"`
}

type evtEvent struct {
	System evtSystem `xml:"System"`
	Data   []evtData `xml:"EventData>Data"`
}

type evtSystem struct {
	EventID     int `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
}

type evtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func (m *Monitor) processEvent(evt evtEvent) {
	dataMap := make(map[string]string)
	for _, d := range evt.Data {
		dataMap[d.Name] = d.Value
	}

	username := dataMap["TargetUserName"]
	if username == "" {
		username = dataMap["SubjectUserName"]
	}
	sourceIP := dataMap["IpAddress"]
	if sourceIP == "-" || sourceIP == "::1" || sourceIP == "127.0.0.1" {
		sourceIP = ""
	}

	logonTypeStr := dataMap["LogonType"]
	logonType := 0
	if logonTypeStr != "" {
		fmt.Sscanf(logonTypeStr, "%d", &logonType)
	}

	// Skip machine account logons (noisy).
	if strings.HasSuffix(username, "$") {
		return
	}
	// Skip system logons (logon type 0 or 5=service).
	if logonType == 0 || logonType == 5 {
		return
	}

	var eventType types.EventType
	var severity types.Severity
	var service string

	switch evt.System.EventID {
	case 4624:
		eventType = types.EventLoginSuccess
		severity = types.SeverityInfo
		service = fmt.Sprintf("logon-type-%d", logonType)
		// Elevate severity for network and RDP logons.
		if logonType == 3 || logonType == 10 {
			severity = types.SeverityLow
		}
	case 4625:
		eventType = types.EventLoginFailed
		severity = types.SeverityMedium
		service = fmt.Sprintf("logon-type-%d", logonType)
	case 4648:
		eventType = types.EventSudoExec
		severity = types.SeverityMedium
		service = "runas"
	default:
		return
	}

	ev := &types.AuthEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      eventType,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      []string{"auth", fmt.Sprintf("event-%d", evt.System.EventID)},
		},
		Username:   username,
		SourceIP:   sourceIP,
		Service:    service,
		TargetUser: dataMap["TargetUserName"],
		LogonType:  logonType,
		WinEventID: evt.System.EventID,
	}

	m.bus.Publish(ev)
	m.log.Info().
		Int("event_id", evt.System.EventID).
		Str("username", username).
		Int("logon_type", logonType).
		Msg("auth event")
}

// ── Polling fallback ──────────────────────────────────────────────────────────
// Preserved from original implementation; activated when EvtSubscribe fails.

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("auth monitor started (polling Security Event Log)")
	return nil
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Track last seen event time to avoid duplicates.
	lastSeen := time.Now()

	// Initial delay to let the system settle.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			evts := m.querySecurityLog(ctx, lastSeen)
			for _, evt := range evts {
				m.processEvent(evt)
			}
			lastSeen = time.Now()
		}
	}
}

func (m *Monitor) querySecurityLog(ctx context.Context, since time.Time) []evtEvent {
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Query recent security events: 4624 (logon success), 4625 (logon failure), 4648 (explicit creds).
	query := fmt.Sprintf(
		"*[System[(EventID=4624 or EventID=4625 or EventID=4648) and TimeCreated[@SystemTime>='%s']]]",
		since.UTC().Format("2006-01-02T15:04:05.000Z"),
	)

	cmd := exec.CommandContext(cmdCtx, "wevtutil", "qe", "Security",
		"/q:"+query, "/c:50", "/rd:true", "/f:xml")
	out, err := cmd.Output()
	if err != nil {
		// wevtutil often returns error if no events match — that is fine.
		m.log.Debug().Err(err).Msg("wevtutil query returned error (may be empty)")
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
		m.log.Debug().Err(err).Msg("failed to parse wevtutil XML output")
		return nil
	}

	return parsed.Events
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
