// internal/playbook/runner.go
//
// Runner evaluates whether a playbook should fire for a given alert/event,
// executes its action chain, and persists a PlaybookRun audit record.

package playbook

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// RunnerStore is the DB interface required by the Runner.
type RunnerStore interface {
	ListEnabledPlaybooks(ctx context.Context, triggerType string) ([]models.Playbook, error)
	InsertPlaybookRun(ctx context.Context, r *models.PlaybookRun) error
	UpdatePlaybookRun(ctx context.Context, id, status, errMsg string, actionsLog []byte) error
	IncrPlaybookRunCount(ctx context.Context, id string) error
	UpdateAlertStatus(ctx context.Context, id, tenantID, status, assignee, notes string) error
}

// Runner dispatches playbooks in response to alerts and XDR events.
type Runner struct {
	store RunnerStore
	lr    LiveResponder
	log   zerolog.Logger
}

// New creates a Runner.
func New(store RunnerStore, lr LiveResponder, log zerolog.Logger) *Runner {
	return &Runner{
		store: store,
		lr:    lr,
		log:   log.With().Str("component", "playbook-runner").Logger(),
	}
}

// OnAlert evaluates all enabled alert-triggered playbooks and fires matching ones.
func (r *Runner) OnAlert(ctx context.Context, alert *models.Alert) {
	playbooks, err := r.store.ListEnabledPlaybooks(ctx, "alert")
	if err != nil {
		r.log.Warn().Err(err).Msg("list playbooks failed")
		return
	}
	for _, pb := range playbooks {
		if matchesAlert(pb, alert) {
			go r.execute(context.Background(), pb, "alert", alert.ID, &ActionContext{
				Alert: alert,
				Store: r.store,
				LR:    r.lr,
			})
		}
	}
}

// OnXdrEvent evaluates all enabled xdr_event-triggered playbooks.
func (r *Runner) OnXdrEvent(ctx context.Context, ev *models.XdrEvent) {
	playbooks, err := r.store.ListEnabledPlaybooks(ctx, "xdr_event")
	if err != nil {
		r.log.Warn().Err(err).Msg("list playbooks failed")
		return
	}
	for _, pb := range playbooks {
		if matchesXdrEvent(pb, ev) {
			go r.execute(context.Background(), pb, "xdr_event", ev.Event.ID, &ActionContext{
				XdrEvent: ev,
				Store:    r.store,
				LR:       r.lr,
			})
		}
	}
}

func (r *Runner) execute(ctx context.Context, pb models.Playbook, triggerType, triggerID string, ac *ActionContext) {
	runID := "run-" + uuid.New().String()
	run := &models.PlaybookRun{
		ID:           runID,
		PlaybookID:   pb.ID,
		PlaybookName: pb.Name,
		TriggerType:  triggerType,
		TriggerID:    triggerID,
		Status:       "running",
		TriggeredBy:  "system",
		ActionsLog:   []byte("[]"),
	}
	if err := r.store.InsertPlaybookRun(ctx, run); err != nil {
		r.log.Warn().Err(err).Str("playbook", pb.ID).Msg("insert run record failed")
	}
	_ = r.store.IncrPlaybookRunCount(ctx, pb.ID)

	var actions []models.PlaybookAction
	if err := json.Unmarshal(pb.Actions, &actions); err != nil {
		r.finishRun(ctx, runID, "failed", "invalid actions JSON: "+err.Error(), nil)
		return
	}

	results := make([]ActionResult, 0, len(actions))
	overallStatus := "success"
	var firstErr string

	for _, act := range actions {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		result := Execute(rctx, act, *ac)
		cancel()
		results = append(results, result)
		if result.Status == "failed" {
			overallStatus = "failed"
			if firstErr == "" {
				firstErr = result.Detail
			}
			r.log.Warn().Str("playbook", pb.Name).Str("action", act.Type).Str("err", result.Detail).Msg("action failed")
		} else {
			r.log.Debug().Str("playbook", pb.Name).Str("action", act.Type).Msg("action succeeded")
		}
	}

	r.finishRun(ctx, runID, overallStatus, firstErr, results)
}

func (r *Runner) finishRun(ctx context.Context, runID, status, errMsg string, results []ActionResult) {
	log, _ := json.Marshal(results)
	if err := r.store.UpdatePlaybookRun(ctx, runID, status, errMsg, log); err != nil {
		r.log.Warn().Err(err).Str("run", runID).Msg("update run record failed")
	}
}

// ── trigger matching ──────────────────────────────────────────────────────────

func matchesAlert(pb models.Playbook, alert *models.Alert) bool {
	var f models.PlaybookTriggerFilter
	if err := json.Unmarshal(pb.TriggerFilter, &f); err != nil {
		return true // no filter = match all
	}
	if f.MinSeverity > 0 && alert.Severity < f.MinSeverity {
		return false
	}
	if len(f.RuleIDs) > 0 && !containsStr(f.RuleIDs, alert.RuleID) {
		return false
	}
	return true
}

func matchesXdrEvent(pb models.Playbook, ev *models.XdrEvent) bool {
	var f models.PlaybookTriggerFilter
	if err := json.Unmarshal(pb.TriggerFilter, &f); err != nil {
		return true
	}
	if len(f.EventTypes) > 0 && !containsStr(f.EventTypes, ev.Event.EventType) {
		return false
	}
	if len(f.SourceTypes) > 0 && !containsStr(f.SourceTypes, ev.SourceType) {
		return false
	}
	return true
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
