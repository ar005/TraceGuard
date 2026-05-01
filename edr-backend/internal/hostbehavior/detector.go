// internal/hostbehavior/detector.go
//
// Tracks per-agent process-launch rate using EWMA and fires an alert when
// the z-score exceeds 3.5 standard deviations — indicating abnormal execution burst.
package hostbehavior

import (
	"context"
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
	hbAlpha   = 0.2
	hbZThresh = 3.5
	hbMinN    = 10
	hbWindow  = time.Minute
)

type agentBaseline struct {
	mu          sync.Mutex
	ewma        float64
	ewmaSq      float64
	n           int
	bucket      int // process count in current window
	bucketStart time.Time
}

// Detector tracks per-host process-launch rates and detects burst anomalies.
type Detector struct {
	mu      sync.RWMutex
	agents  map[string]*agentBaseline // agentID -> baseline
	store   *store.Store
	alertFn func(context.Context, *models.Alert)
	log     zerolog.Logger
}

// New creates a new host behavior Detector.
func New(st *store.Store, alertFn func(context.Context, *models.Alert), log zerolog.Logger) *Detector {
	return &Detector{
		agents:  make(map[string]*agentBaseline),
		store:   st,
		alertFn: alertFn,
		log:     log.With().Str("component", "host-behavior").Logger(),
	}
}

// Observe is called on every PROCESS_CREATE event.
func (d *Detector) Observe(ctx context.Context, ev *models.XdrEvent) {
	if ev.EventType != "PROCESS_CREATE" {
		return
	}
	d.mu.Lock()
	bl, ok := d.agents[ev.AgentID]
	if !ok {
		bl = &agentBaseline{bucketStart: time.Now()}
		d.agents[ev.AgentID] = bl
	}
	d.mu.Unlock()

	bl.mu.Lock()
	defer bl.mu.Unlock()

	now := time.Now()
	if now.Sub(bl.bucketStart) >= hbWindow {
		// flush bucket into EWMA
		obs := float64(bl.bucket)
		dev := obs - bl.ewma
		bl.ewma = hbAlpha*obs + (1-hbAlpha)*bl.ewma
		bl.ewmaSq = hbAlpha*(dev*dev) + (1-hbAlpha)*bl.ewmaSq
		bl.n++
		bl.bucket = 0
		bl.bucketStart = now

		if bl.n >= hbMinN {
			sigma := math.Sqrt(bl.ewmaSq)
			if sigma > 0 {
				z := dev / sigma
				if z > hbZThresh {
					go d.fireAlert(context.Background(), ev, obs, bl.ewma, z)
				}
			}
		}
	}
	bl.bucket++
}

func (d *Detector) fireAlert(ctx context.Context, ev *models.XdrEvent, obs, mean, z float64) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	alert := &models.Alert{
		ID:    "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		AgentID:  ev.AgentID,
		Title: fmt.Sprintf("Process Burst Anomaly on %s", ev.Hostname),
		Description: fmt.Sprintf(
			"Host %s launched %.0f processes in one minute (baseline: %.1f, z-score: %.1f). Possible malware or script execution.",
			ev.Hostname, obs, mean, z),
		Severity:    3,
		Status:      "OPEN",
		RuleID:      "rule-host-process-anomaly",
		RuleName:    "Host Process Burst Anomaly",
		MitreIDs:    []string{"T1059", "T1204"},
		SourceTypes: []string{"endpoint"},
	}
	d.alertFn(ctx, alert)
	d.log.Warn().Str("agent", ev.AgentID).Float64("z", z).Msg("process burst anomaly")
}
