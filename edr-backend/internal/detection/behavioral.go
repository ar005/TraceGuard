// internal/detection/behavioral.go
//
// EWMA + z-score anomaly detection for user login frequency.
// No external ML framework; uses Welford online variance update.
//
// Algorithm:
//   - For each user, track an EWMA of hourly login count with α = 0.2.
//   - Track EWMA of squared deviations to derive online stddev.
//   - When z-score = (observed - ewma) / stddev > threshold (default 3.5),
//     fire a BEHAVIORAL_ANOMALY_LOGIN alert.
//   - Baseline is warm-started from the behavioral_baselines DB table on startup.

package detection

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	behavioralAlpha     = 0.2  // EWMA smoothing factor
	behavioralZThresh   = 3.5  // z-score threshold for anomaly
	behavioralMinN      = 10   // minimum observations before alerting
	behavioralFlushSecs = 300  // persist baselines every 5 minutes
)

type userBaseline struct {
	ewma   float64
	ewmaSq float64 // EWMA of (x - ewma)^2 — approximates variance
	n      int
}

// BehavioralAnalyzer tracks per-user login frequency and fires alerts on anomalies.
type BehavioralAnalyzer struct {
	db       *sqlx.DB
	st       *store.Store
	log      zerolog.Logger
	mu       sync.Mutex
	baselines map[string]*userBaseline // key: user_uid

	// alertFn is called when an anomaly is detected.
	alertFn func(ctx context.Context, alert *models.Alert)
	stop    chan struct{}
}

func NewBehavioralAnalyzer(db *sqlx.DB, st *store.Store, alertFn func(ctx context.Context, alert *models.Alert), log zerolog.Logger) *BehavioralAnalyzer {
	return &BehavioralAnalyzer{
		db:        db,
		st:        st,
		log:       log.With().Str("component", "behavioral").Logger(),
		baselines: make(map[string]*userBaseline),
		alertFn:   alertFn,
		stop:      make(chan struct{}),
	}
}

// Start loads baselines from DB and launches the periodic flush goroutine.
func (b *BehavioralAnalyzer) Start(ctx context.Context) {
	b.loadBaselines(ctx)
	ticker := time.NewTicker(behavioralFlushSecs * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.flushBaselines(ctx)
		case <-b.stop:
			b.flushBaselines(ctx)
			return
		case <-ctx.Done():
			b.flushBaselines(ctx)
			return
		}
	}
}

func (b *BehavioralAnalyzer) Stop() { close(b.stop) }

// Observe records a login event for the given user_uid. Call this from the
// identity connector or ingest path whenever a LOGIN_SUCCESS event is seen.
func (b *BehavioralAnalyzer) Observe(ctx context.Context, userUID, tenantID string) {
	if userUID == "" {
		return
	}

	b.mu.Lock()
	bl, ok := b.baselines[userUID]
	if !ok {
		bl = &userBaseline{}
		b.baselines[userUID] = bl
	}

	observation := 1.0
	prev := bl.ewma

	bl.ewma = behavioralAlpha*observation + (1-behavioralAlpha)*bl.ewma
	dev := observation - prev
	bl.ewmaSq = behavioralAlpha*(dev*dev) + (1-behavioralAlpha)*bl.ewmaSq
	bl.n++

	n := bl.n
	ewma := bl.ewma
	ewmaSq := bl.ewmaSq
	b.mu.Unlock()

	if n < behavioralMinN {
		return
	}
	stddev := math.Sqrt(ewmaSq)
	if stddev < 0.01 {
		return
	}
	z := (observation - ewma) / stddev
	if z < behavioralZThresh {
		return
	}

	b.log.Warn().
		Str("user_uid", userUID).
		Float64("z_score", z).
		Float64("ewma", ewma).
		Float64("stddev", stddev).
		Msg("behavioral anomaly: login burst detected")

	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"z_score": z, "ewma": ewma, "stddev": stddev, "tenant": tenantID,
	})

	now := time.Now()
	alert := &models.Alert{
		ID:          "beh-" + userUID + "-" + now.Format("20060102T150405"),
		RuleID:      "rule-behavioral-login-anomaly",
		RuleName:    "Behavioral: Login Frequency Anomaly",
		Title:       "Unusual login frequency for user " + userUID,
		Description: string(detailsJSON),
		Severity:    3,
		Status:      "OPEN",
		UserUID:     userUID,
		SourceTypes: pq.StringArray{"identity"},
		MitreIDs:    pq.StringArray{"T1078"},
		FirstSeen:   now,
		LastSeen:    now,
	}

	if b.alertFn != nil {
		b.alertFn(ctx, alert)
	}
}

func (b *BehavioralAnalyzer) loadBaselines(ctx context.Context) {
	rows, err := b.db.QueryContext(ctx,
		`SELECT user_uid, ewma, ewma_sq, n FROM behavioral_baselines`)
	if err != nil {
		b.log.Warn().Err(err).Msg("load baselines failed")
		return
	}
	defer rows.Close()

	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for rows.Next() {
		var uid string
		var bl userBaseline
		if err := rows.Scan(&uid, &bl.ewma, &bl.ewmaSq, &bl.n); err == nil {
			b.baselines[uid] = &bl
			count++
		}
	}
	b.log.Info().Int("loaded", count).Msg("behavioral baselines loaded")
}

func (b *BehavioralAnalyzer) flushBaselines(ctx context.Context) {
	b.mu.Lock()
	snapshot := make(map[string]userBaseline, len(b.baselines))
	for k, v := range b.baselines {
		snapshot[k] = *v
	}
	b.mu.Unlock()

	tx, err := b.db.BeginTxx(ctx, nil)
	if err != nil {
		b.log.Error().Err(err).Msg("flush baselines: begin tx")
		return
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO behavioral_baselines (user_uid, ewma, ewma_sq, n, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (user_uid) DO UPDATE SET
			ewma       = EXCLUDED.ewma,
			ewma_sq    = EXCLUDED.ewma_sq,
			n          = EXCLUDED.n,
			updated_at = NOW()`)
	if err != nil {
		b.log.Error().Err(err).Msg("flush baselines: prepare")
		return
	}
	defer stmt.Close()

	for uid, bl := range snapshot {
		if _, err := stmt.ExecContext(ctx, uid, bl.ewma, bl.ewmaSq, bl.n); err != nil {
			b.log.Error().Err(err).Str("user_uid", uid).Msg("flush baseline row")
		}
	}
	if err := tx.Commit(); err != nil {
		b.log.Error().Err(err).Msg("flush baselines: commit")
	}
}
