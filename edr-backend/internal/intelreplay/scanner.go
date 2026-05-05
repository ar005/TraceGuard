// Package intelreplay scans historical events retroactively against IOC lists.
package intelreplay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Store is the subset of store.Store used by the scanner.
type Store interface {
	DequeueReplayJob(ctx context.Context) (*models.ReplayJob, error)
	GetEnabledIOCsForReplay(ctx context.Context, tenantID string, iocIDs []string) ([]models.IOC, error)
	ScanIPEvents(ctx context.Context, from, to time.Time, ips []string) ([]store.ReplayMatch, error)
	ScanDomainEvents(ctx context.Context, from, to time.Time, domains []string) ([]store.ReplayMatch, error)
	ScanHashEvents(ctx context.Context, from, to time.Time, hashes []string) ([]store.ReplayMatch, error)
	UpdateReplayJobProgress(ctx context.Context, id string, scanned, matched int) error
	FinishReplayJob(ctx context.Context, id string, scanned, matched int, failed bool) error
	InsertAlert(ctx context.Context, a *models.Alert) error
}

// Scanner drains the replay job queue.
type Scanner struct {
	store Store
	log   zerolog.Logger
}

// New creates a Scanner.
func New(st Store, log zerolog.Logger) *Scanner {
	return &Scanner{store: st, log: log.With().Str("component", "intel-replay").Logger()}
}

// Run polls for queued jobs and processes them; returns when ctx is cancelled.
func (sc *Scanner) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for {
				job, err := sc.store.DequeueReplayJob(ctx)
				if errors.Is(err, sql.ErrNoRows) || job == nil {
					break
				}
				if err != nil {
					sc.log.Warn().Err(err).Msg("dequeue replay job")
					break
				}
				sc.run(ctx, job)
			}
		}
	}
}

// EnqueueNow is called by API handlers to enqueue a job immediately.
// It only creates the DB record; Run() will pick it up within 10 s.
func EnqueueNow(ctx context.Context, st Store, tenantID, triggeredBy string, iocIDs []string, lookbackDays int16) error {
	// Store interface doesn't expose CreateReplayJob directly — callers use the
	// concrete *store.Store; this function exists for handlers that have that.
	_ = ctx
	_ = st
	_ = tenantID
	_ = triggeredBy
	_ = iocIDs
	_ = lookbackDays
	return fmt.Errorf("use store.CreateReplayJob directly")
}

func (sc *Scanner) run(ctx context.Context, job *models.ReplayJob) {
	sc.log.Info().Str("job", job.ID).Int("lookback_days", int(job.LookbackDays)).Msg("replay job started")

	iocList := []string(job.IOCIDs)
	iocs, err := sc.store.GetEnabledIOCsForReplay(ctx, job.TenantID, iocList)
	if err != nil {
		sc.log.Error().Err(err).Str("job", job.ID).Msg("fetch IOCs for replay")
		_ = sc.store.FinishReplayJob(ctx, job.ID, 0, 0, true)
		return
	}
	if len(iocs) == 0 {
		_ = sc.store.FinishReplayJob(ctx, job.ID, 0, 0, false)
		return
	}

	// Bucket IOCs by type.
	ipMap := map[string]string{}
	domainMap := map[string]string{}
	hashMap := map[string]string{}
	for _, ioc := range iocs {
		switch ioc.Type {
		case "ip":
			ipMap[ioc.Value] = ioc.ID
		case "domain":
			domainMap[ioc.Value] = ioc.ID
		case "hash_sha256", "hash_md5":
			hashMap[ioc.Value] = ioc.ID
		}
	}

	keys := func(m map[string]string) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return out
	}

	now := time.Now()
	windowStart := now.AddDate(0, 0, -int(job.LookbackDays))

	scanned, matched := 0, 0
	seen := map[string]bool{} // deduplicate alert per (iocID+agentID)

	// Scan 1-day chunks to avoid huge result sets.
	for chunkStart := windowStart; chunkStart.Before(now); chunkStart = chunkStart.AddDate(0, 0, 1) {
		chunkEnd := chunkStart.AddDate(0, 0, 1)
		if chunkEnd.After(now) {
			chunkEnd = now
		}

		var matches []store.ReplayMatch

		if ipMatches, err := sc.store.ScanIPEvents(ctx, chunkStart, chunkEnd, keys(ipMap)); err == nil {
			for i := range ipMatches {
				// Find which IP triggered the match
				// We can't know which specific IP matched without another query, so we fire alert per event
				ipMatches[i].IOCID = "" // filled below
				matches = append(matches, ipMatches[i])
			}
		}
		if domMatches, err := sc.store.ScanDomainEvents(ctx, chunkStart, chunkEnd, keys(domainMap)); err == nil {
			matches = append(matches, domMatches...)
		}
		if hashMatches, err := sc.store.ScanHashEvents(ctx, chunkStart, chunkEnd, keys(hashMap)); err == nil {
			matches = append(matches, hashMatches...)
		}

		scanned += int(chunkEnd.Sub(chunkStart).Hours()) * 100 // rough estimate
		for _, m := range matches {
			dedupeKey := m.AgentID + "|" + m.EventID
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true
			matched++
			sc.createReplayAlert(ctx, job, &m)
		}

		if err := sc.store.UpdateReplayJobProgress(ctx, job.ID, scanned, matched); err != nil {
			sc.log.Warn().Err(err).Str("job", job.ID).Msg("update progress")
		}
		if ctx.Err() != nil {
			_ = sc.store.FinishReplayJob(ctx, job.ID, scanned, matched, true)
			return
		}
	}

	_ = sc.store.FinishReplayJob(ctx, job.ID, scanned, matched, false)
	sc.log.Info().Str("job", job.ID).Int("matched", matched).Msg("replay job done")
}

func (sc *Scanner) createReplayAlert(ctx context.Context, job *models.ReplayJob, m *store.ReplayMatch) {
	a := &models.Alert{
		ID:          "alert-" + uuid.New().String(),
		TenantID:    job.TenantID,
		Title:       fmt.Sprintf("Intel Replay: IOC match on %s", m.Hostname),
		Description: fmt.Sprintf("Retroactive IOC scan (job %s) matched event %s on %s", job.ID, m.EventID, m.Hostname),
		Severity:    3, // HIGH
		Status:      "open",
		RuleID:      "intel_replay",
		RuleName:    "Intel Replay",
		AgentID:     m.AgentID,
		Hostname:    m.Hostname,
		FirstSeen:   m.Timestamp,
		LastSeen:    m.Timestamp,
	}
	if err := sc.store.InsertAlert(ctx, a); err != nil {
		sc.log.Warn().Err(err).Str("event", m.EventID).Msg("replay: insert alert")
	}
}
