// Package huntscheduler runs saved hunt queries on a cron schedule and fires
// alerts when matches are found.
package huntscheduler

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Scheduler checks for due hunt schedules every minute and executes them.
type Scheduler struct {
	st  *store.Store
	log zerolog.Logger
}

func New(st *store.Store, log zerolog.Logger) *Scheduler {
	return &Scheduler{st: st, log: log}
}

// Run ticks every minute checking for due schedules.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDue(ctx)
		}
	}
}

func (s *Scheduler) runDue(ctx context.Context) {
	schedules, err := s.st.ListDueHuntSchedules(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("huntscheduler: list due schedules")
		return
	}
	for _, hs := range schedules {
		go s.execute(ctx, hs)
	}
}

func (s *Scheduler) execute(ctx context.Context, hs models.HuntSchedule) {
	run := &models.HuntScheduleRun{
		ScheduleID: hs.ID,
		TenantID:   hs.TenantID,
		Status:     "running",
	}
	if err := s.st.CreateHuntScheduleRun(ctx, run); err != nil {
		s.log.Error().Err(err).Str("schedule", hs.ID).Msg("huntscheduler: create run")
		return
	}

	// Advance next_run_at immediately so concurrent ticks don't double-fire.
	next := NextCronTime(hs.CronExpr, time.Now())
	_ = s.st.AdvanceHuntSchedule(ctx, hs.ID, next)

	hunt, err := s.st.GetSavedHunt(ctx, hs.SavedHuntID, hs.TenantID)
	if err != nil {
		_ = s.st.FinishHuntScheduleRun(ctx, run.ID, 0, 0, "error", "saved hunt not found")
		return
	}

	events, total, queryErr := s.st.HuntQuery(ctx, hs.TenantID, hunt.Query, 1000)
	if queryErr != nil {
		_ = s.st.FinishHuntScheduleRun(ctx, run.ID, 0, 0, "error", queryErr.Error())
		s.log.Error().Err(queryErr).Str("schedule", hs.ID).Msg("huntscheduler: query failed")
		return
	}

	hitCount := len(events)
	_ = s.st.FinishHuntScheduleRun(ctx, run.ID, total, hitCount, "ok", "")

	if hitCount > 0 && hs.AlertOnHit {
		s.fireAlert(ctx, hs, hunt, hitCount)
	}

	s.log.Info().
		Str("schedule", hs.Name).
		Int("hits", hitCount).
		Time("next", next).
		Msg("huntscheduler: run complete")
}

func (s *Scheduler) fireAlert(ctx context.Context, hs models.HuntSchedule, hunt *models.SavedHunt, hitCount int) {
	alert := &models.Alert{
		TenantID:    hs.TenantID,
		AgentID:     "scheduled-hunt",
		Severity:    2, // medium
		Title:       fmt.Sprintf("Scheduled hunt hit: %s (%d matches)", hs.Name, hitCount),
		Description: fmt.Sprintf("Hunt query '%s' matched %d events.", hunt.Name, hitCount),
		RuleID:      hs.ID,
		RuleName:    hs.Name,
	}
	if err := s.st.InsertAlert(ctx, alert); err != nil {
		s.log.Error().Err(err).Str("schedule", hs.ID).Msg("huntscheduler: create alert")
	}
}

// NextCronTime computes the next fire time for a simplified cron expression.
// Supports standard 5-field cron: minute hour dom month dow.
// Falls back to +1h on parse error.
func NextCronTime(expr string, from time.Time) time.Time {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return from.Add(time.Hour)
	}
	// Parse interval shorthand: */N in minute field with * everywhere else.
	if strings.HasPrefix(fields[0], "*/") && allStar(fields[1:]) {
		n, err := strconv.Atoi(strings.TrimPrefix(fields[0], "*/"))
		if err != nil || n <= 0 {
			return from.Add(time.Hour)
		}
		return from.Add(time.Duration(n) * time.Minute)
	}
	// Parse hourly: 0 */H * * *
	if fields[0] == "0" && strings.HasPrefix(fields[1], "*/") && allStar(fields[2:]) {
		n, err := strconv.Atoi(strings.TrimPrefix(fields[1], "*/"))
		if err != nil || n <= 0 {
			return from.Add(time.Hour)
		}
		return from.Add(time.Duration(n) * time.Hour)
	}
	// Daily: 0 H * * *
	if fields[0] == "0" && allStar(fields[2:]) {
		h, err := strconv.Atoi(fields[1])
		if err != nil {
			return from.Add(24 * time.Hour)
		}
		next := time.Date(from.Year(), from.Month(), from.Day(), h, 0, 0, 0, from.Location())
		if !next.After(from) {
			next = next.Add(24 * time.Hour)
		}
		return next
	}
	// Default: 1 hour later.
	return from.Add(time.Hour)
}

func allStar(fields []string) bool {
	for _, f := range fields {
		if f != "*" {
			return false
		}
	}
	return true
}
