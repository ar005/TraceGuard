// Package tip manages bi-directional sync with a MISP Threat Intelligence Platform.
package tip

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/mispfeed"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Manager handles TIP pull/push lifecycle.
type Manager struct {
	store  *store.Store
	log    zerolog.Logger
	ticker *time.Ticker
	stop   chan struct{}
}

// New creates a Manager and starts the background scheduler.
func New(st *store.Store, log zerolog.Logger) *Manager {
	m := &Manager{
		store: st,
		log:   log.With().Str("component", "tip").Logger(),
		stop:  make(chan struct{}),
	}
	go m.scheduler()
	return m
}

// Stop shuts down the background scheduler.
func (m *Manager) Stop() { close(m.stop) }

func (m *Manager) scheduler() {
	// Re-check settings every 15 minutes; act only when auto_pull is enabled and interval elapsed.
	tick := time.NewTicker(15 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-tick.C:
			m.maybeAutoPull(context.Background())
			m.maybeAutoPush(context.Background())
		}
	}
}

func (m *Manager) maybeAutoPull(ctx context.Context) {
	cfg, err := m.store.GetTIPSettings(ctx)
	if err != nil || !cfg.Enabled || !cfg.AutoPull || cfg.MISPUrl == "" {
		return
	}
	due := cfg.LastPullAt == nil || time.Since(*cfg.LastPullAt) >= time.Duration(cfg.PullIntervalHours)*time.Hour
	if !due {
		return
	}
	if _, err := m.Pull(ctx); err != nil {
		m.log.Error().Err(err).Msg("auto pull failed")
	}
}

func (m *Manager) maybeAutoPush(ctx context.Context) {
	cfg, err := m.store.GetTIPSettings(ctx)
	if err != nil || !cfg.Enabled || !cfg.AutoPushMatches || cfg.MISPUrl == "" {
		return
	}
	if _, err := m.PushMatches(ctx); err != nil {
		m.log.Error().Err(err).Msg("auto push-matches failed")
	}
}

// Pull fetches MISP attributes and upserts them as TraceGuard IOCs.
// Returns the number of IOCs imported.
func (m *Manager) Pull(ctx context.Context) (int, error) {
	cfg, err := m.store.GetTIPSettings(ctx)
	if err != nil {
		return 0, err
	}
	if cfg.MISPUrl == "" {
		return 0, fmt.Errorf("MISP URL not configured")
	}

	client := mispfeed.New(cfg.MISPUrl, cfg.MISPApiKey)
	attrs, err := client.FetchAttributes(ctx)
	if err != nil {
		_ = m.store.RecordTIPSync(ctx, "pull", "error", 0, err.Error())
		return 0, err
	}

	imported := 0
	for _, a := range attrs {
		ioc := &models.IOC{
			ID:          uuid.New().String(),
			TenantID:    cfg.TenantID,
			Value:       a.Value,
			Type:        a.IOCType,
			Source:      "misp",
			Description: a.Comment,
			Tags:        pq.StringArray(a.Tags),
			Enabled:     true,
			CreatedAt:   time.Now(),
		}
		if err := m.store.UpsertIOCFromTIP(ctx, ioc); err != nil {
			m.log.Warn().Err(err).Str("value", a.Value).Msg("upsert IOC from TIP failed")
			continue
		}
		imported++
	}

	now := time.Now()
	_ = m.store.UpdateTIPLastPull(ctx, now)
	_ = m.store.RecordTIPSync(ctx, "pull", "ok", imported, "")
	m.log.Info().Int("imported", imported).Msg("MISP pull complete")
	return imported, nil
}

// Push exports all active TraceGuard IOCs to MISP.
// Returns the number of IOCs pushed.
func (m *Manager) Push(ctx context.Context) (int, error) {
	cfg, err := m.store.GetTIPSettings(ctx)
	if err != nil {
		return 0, err
	}
	if cfg.MISPUrl == "" {
		return 0, fmt.Errorf("MISP URL not configured")
	}

	iocs, err := m.store.ListActiveIOCs(ctx, cfg.TenantID)
	if err != nil {
		return 0, err
	}

	pusher := mispfeed.NewPusher(cfg.MISPUrl, cfg.MISPApiKey)
	pushed, err := pusher.PushIOCs(ctx, iocs)
	if err != nil {
		_ = m.store.RecordTIPSync(ctx, "push", "error", pushed, err.Error())
		return pushed, err
	}

	now := time.Now()
	_ = m.store.UpdateTIPLastPush(ctx, now)
	_ = m.store.RecordTIPSync(ctx, "push", "ok", pushed, "")
	m.log.Info().Int("pushed", pushed).Msg("MISP push complete")
	return pushed, nil
}

// PushMatches promotes IOCs that were matched in recent alerts but not yet sent to MISP.
func (m *Manager) PushMatches(ctx context.Context) (int, error) {
	cfg, err := m.store.GetTIPSettings(ctx)
	if err != nil {
		return 0, err
	}
	if cfg.MISPUrl == "" {
		return 0, nil
	}

	iocs, err := m.store.GetIOCsForTIPPromotion(ctx, cfg.TenantID)
	if err != nil || len(iocs) == 0 {
		return 0, err
	}

	pusher := mispfeed.NewPusher(cfg.MISPUrl, cfg.MISPApiKey)
	pushed, err := pusher.PushIOCs(ctx, iocs)
	if pushed > 0 {
		ids := make([]string, len(iocs))
		for i, ioc := range iocs {
			ids[i] = ioc.ID
		}
		_ = m.store.MarkIOCsTIPPushed(ctx, ids)
		now := time.Now()
		_ = m.store.UpdateTIPLastPush(ctx, now)
		_ = m.store.RecordTIPSync(ctx, "push_matches", "ok", pushed, "")
	}
	return pushed, err
}
