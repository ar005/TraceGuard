// internal/lateral/detector.go
//
// LateralMovementDetector identifies credential reuse across multiple hosts:
// same user_uid authenticated on >2 distinct agents within 30 minutes.
// Runs as a periodic sweep against the login_sessions table.

package lateral

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
	lateralWindow    = 30 * time.Minute
	lateralThresh    = 2 // >2 distinct agents
	sweepInterval    = 5 * time.Minute
)

type LateralStore interface {
	LateralMovementQuery(ctx context.Context, tenantID string, window time.Duration) ([]models.LateralHit, error)
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Detector struct {
	store   LateralStore
	log     zerolog.Logger
	mu      sync.Mutex
	alerted map[string]time.Time // userUID -> last alert time (debounce 1h)
}

func New(st *store.Store, log zerolog.Logger) *Detector {
	return &Detector{
		store:   st,
		log:     log.With().Str("component", "lateral-movement-detector").Logger(),
		alerted: make(map[string]time.Time),
	}
}

// Run starts the periodic sweep. Blocks until ctx is cancelled.
func (d *Detector) Run(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	d.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.sweep(ctx)
		}
	}
}

func (d *Detector) sweep(ctx context.Context) {
	hits, err := d.store.LateralMovementQuery(ctx, "", lateralWindow)
	if err != nil {
		d.log.Warn().Err(err).Msg("lateral movement sweep failed")
		return
	}
	for _, hit := range hits {
		if hit.AgentCount <= lateralThresh {
			continue
		}
		d.mu.Lock()
		last, seen := d.alerted[hit.UserUID]
		if seen && time.Since(last) < time.Hour {
			d.mu.Unlock()
			continue
		}
		d.alerted[hit.UserUID] = time.Now()
		d.mu.Unlock()

		go d.fireAlert(ctx, hit)
	}
}

func (d *Detector) fireAlert(ctx context.Context, hit models.LateralHit) {
	hosts := ""
	for i, h := range hit.Hostnames {
		if i > 0 {
			hosts += ", "
		}
		hosts += h
	}
	firstAgent := ""
	if len(hit.AgentIDs) > 0 {
		firstAgent = hit.AgentIDs[0]
	}
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: hit.TenantID,
		Title:    fmt.Sprintf("Lateral Movement: %s on %d hosts", hit.UserUID, hit.AgentCount),
		Description: fmt.Sprintf(
			"User %s authenticated on %d different hosts within 30 minutes: %s. Possible credential theft or lateral movement.",
			hit.UserUID, hit.AgentCount, hosts),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-lateral-movement",
		RuleName:    "Lateral Movement",
		MitreIDs:    []string{"T1021", "T1550", "T1078"},
		AgentID:     firstAgent,
		UserUID:     hit.UserUID,
		SourceTypes: []string{"identity", "endpoint"},
	}
	if err := d.store.InsertAlert(ctx, alert); err != nil {
		d.log.Warn().Err(err).Str("uid", hit.UserUID).Msg("lateral movement alert insert failed")
	} else {
		d.log.Warn().Str("uid", hit.UserUID).Int("agents", hit.AgentCount).Msg("LATERAL MOVEMENT ALERT")
	}
}
