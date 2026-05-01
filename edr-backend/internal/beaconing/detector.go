// internal/beaconing/detector.go
//
// BeaconingDetector identifies C2 heartbeat traffic: regular outbound connections
// to the same dst_ip:port. Fires an alert when:
//   - >= 6 connections observed within 2 hours
//   - coefficient of variation (stddev/mean) of intervals < 0.2
//   - mean interval between 5s and 3600s

package beaconing

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	minObservations = 6
	maxCV           = 0.2
	minIntervalS    = 5.0
	maxIntervalS    = 3600.0
	beaconWindow    = 2 * time.Hour
)

type BeaconingStore interface {
	MarkBeaconingAlertFired(ctx context.Context, agentID, dstIP string, dstPort int) error
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Detector struct {
	store     BeaconingStore
	log       zerolog.Logger
	mu        sync.Mutex
	connTimes map[string][]time.Time // "agentID|ip:port" -> timestamps
	alerted   map[string]bool
}

func New(st *store.Store, log zerolog.Logger) *Detector {
	return &Detector{
		store:     st,
		log:       log.With().Str("component", "beaconing-detector").Logger(),
		connTimes: make(map[string][]time.Time),
		alerted:   make(map[string]bool),
	}
}

func (d *Detector) Observe(ctx context.Context, ev *models.XdrEvent) {
	if ev.DstIP == nil {
		return
	}
	if ev.Event.EventType != "NETWORK_CONNECTION" && ev.Event.EventType != "NETWORK_CONNECT" {
		return
	}

	dstPort := 0
	var payload map[string]interface{}
	if len(ev.Event.Payload) > 0 {
		_ = json.Unmarshal(ev.Event.Payload, &payload)
	}
	if p, ok := payload["dst_port"].(float64); ok {
		dstPort = int(p)
	}

	key := fmt.Sprintf("%s|%s:%d", ev.AgentID, ev.DstIP.String(), dstPort)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.alerted[key] {
		return
	}

	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	cutoff := ts.Add(-beaconWindow)
	times := d.connTimes[key]
	fresh := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, ts)
	d.connTimes[key] = fresh

	if len(fresh) < minObservations {
		return
	}

	intervals := make([]float64, len(fresh)-1)
	for i := 1; i < len(fresh); i++ {
		intervals[i-1] = fresh[i].Sub(fresh[i-1]).Seconds()
	}

	mean := meanF(intervals)
	if mean < minIntervalS || mean > maxIntervalS {
		return
	}
	cv := stddevF(intervals) / mean
	if cv > maxCV {
		return
	}

	d.alerted[key] = true
	go func() {
		alertCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d.fireAlert(alertCtx, ev, dstPort, mean, cv)
	}()
}

func (d *Detector) fireAlert(ctx context.Context, ev *models.XdrEvent, dstPort int, meanS, cv float64) {
	dstIPStr := ev.DstIP.String()
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title: fmt.Sprintf("C2 Beaconing Detected: %s → %s:%d",
			ev.AgentID, dstIPStr, dstPort),
		Description: fmt.Sprintf(
			"Outbound connections to %s:%d at regular ~%.1fs intervals (CV=%.2f) — possible C2 beacon.",
			dstIPStr, dstPort, meanS, cv),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-beaconing",
		RuleName:    "C2 Beaconing",
		MitreIDs:    []string{"T1071", "T1571"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		SourceTypes: []string{"network"},
	}
	if err := d.store.InsertAlert(ctx, alert); err != nil {
		d.log.Warn().Err(err).Str("agent_id", ev.AgentID).Msg("beaconing alert insert failed")
		return
	}
	_ = d.store.MarkBeaconingAlertFired(ctx, ev.AgentID, dstIPStr, dstPort)
	d.log.Warn().Str("agent_id", ev.AgentID).
		Str("dst", fmt.Sprintf("%s:%d", dstIPStr, dstPort)).
		Float64("mean_s", meanS).Float64("cv", cv).
		Msg("BEACONING ALERT FIRED")
}

func meanF(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func stddevF(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	m := meanF(v)
	sum := 0.0
	for _, x := range v {
		sum += (x - m) * (x - m)
	}
	return math.Sqrt(sum / float64(len(v)))
}
