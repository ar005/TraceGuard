// internal/netthreat/detector.go
//
// Detects port scanning (>50 unique dst_ports within 60s) and data exfiltration
// (>100MB outbound within 5 minutes) from network events.
package netthreat

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	portScanWindow   = 60 * time.Second
	portScanThresh   = 50
	exfilWindow      = 5 * time.Minute
	exfilThreshBytes = 100 * 1024 * 1024 // 100 MB
)

type portEntry struct {
	ports map[int]struct{}
	since time.Time
}

type exfilEntry struct {
	bytes uint64
	since time.Time
}

// Detector tracks per-agent network behaviour and fires alerts on anomalies.
type Detector struct {
	mu         sync.Mutex
	portState  map[string]*portEntry  // agentID -> ports seen in window
	exfilState map[string]*exfilEntry // agentID -> bytes out in window
	alerted    map[string]time.Time   // agentID+type -> last alert (1h debounce)
	store      *store.Store
	alertFn    func(context.Context, *models.Alert)
	log        zerolog.Logger
}

// New creates a new network threat Detector.
func New(st *store.Store, alertFn func(context.Context, *models.Alert), log zerolog.Logger) *Detector {
	return &Detector{
		portState:  make(map[string]*portEntry),
		exfilState: make(map[string]*exfilEntry),
		alerted:    make(map[string]time.Time),
		store:      st,
		alertFn:    alertFn,
		log:        log.With().Str("component", "net-threat").Logger(),
	}
}

// Observe is called on every NETWORK_CONNECTION event.
func (d *Detector) Observe(ctx context.Context, ev *models.XdrEvent) {
	if ev.EventType != "NETWORK_CONNECTION" {
		return
	}
	d.observePortScan(ctx, ev)
	d.observeExfil(ctx, ev)
}

func (d *Detector) observePortScan(ctx context.Context, ev *models.XdrEvent) {
	if ev.DstPort == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	e, ok := d.portState[ev.AgentID]
	if !ok || time.Since(e.since) > portScanWindow {
		e = &portEntry{ports: make(map[int]struct{}), since: time.Now()}
		d.portState[ev.AgentID] = e
	}
	e.ports[ev.DstPort] = struct{}{}

	if len(e.ports) < portScanThresh {
		return
	}
	key := ev.AgentID + ":portscan"
	if last, seen := d.alerted[key]; seen && time.Since(last) < time.Hour {
		return
	}
	d.alerted[key] = time.Now()
	e.ports = make(map[int]struct{}) // reset
	go d.firePortScan(context.Background(), ev, portScanThresh)
}

func (d *Detector) observeExfil(ctx context.Context, ev *models.XdrEvent) {
	if ev.BytesOut == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	e, ok := d.exfilState[ev.AgentID]
	if !ok || time.Since(e.since) > exfilWindow {
		e = &exfilEntry{since: time.Now()}
		d.exfilState[ev.AgentID] = e
	}
	e.bytes += ev.BytesOut

	if e.bytes < exfilThreshBytes {
		return
	}
	key := ev.AgentID + ":exfil"
	if last, seen := d.alerted[key]; seen && time.Since(last) < time.Hour {
		return
	}
	d.alerted[key] = time.Now()
	mb := e.bytes / (1024 * 1024)
	e.bytes = 0 // reset
	go d.fireExfil(context.Background(), ev, mb)
}

func (d *Detector) firePortScan(ctx context.Context, ev *models.XdrEvent, portCount int) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	d.alertFn(ctx, &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		AgentID:  ev.AgentID,
		Title:    fmt.Sprintf("Port Scan Detected on %s", ev.Hostname),
		Description: fmt.Sprintf(
			"Host %s connected to %d distinct destination ports within 60 seconds. Possible reconnaissance or worm activity.",
			ev.Hostname, portCount),
		Severity:    3,
		Status:      "OPEN",
		RuleID:      "rule-port-scan",
		RuleName:    "Port Scan",
		MitreIDs:    []string{"T1046"},
		SourceTypes: []string{"endpoint", "network"},
	})
	d.log.Warn().Str("agent", ev.AgentID).Int("ports", portCount).Msg("port scan detected")
}

func (d *Detector) fireExfil(ctx context.Context, ev *models.XdrEvent, mb uint64) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dstIP := ""
	if ev.DstIP != nil {
		dstIP = ev.DstIP.String()
	}
	d.alertFn(ctx, &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		AgentID:  ev.AgentID,
		Title:    fmt.Sprintf("Possible Data Exfiltration on %s", ev.Hostname),
		Description: fmt.Sprintf(
			"Host %s sent %d MB outbound within 5 minutes to %s. Possible data exfiltration.",
			ev.Hostname, mb, dstIP),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-data-exfil",
		RuleName:    "Data Exfiltration",
		MitreIDs:    []string{"T1048", "T1041"},
		SourceTypes: []string{"endpoint", "network"},
	})
	d.log.Warn().Str("agent", ev.AgentID).Uint64("mb", mb).Msg("data exfil detected")
}
