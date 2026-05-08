// internal/autoremediate/engine.go
//
// Evaluates each fired alert against auto_remediation_rules and triggers configured actions.
package autoremediate

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Engine evaluates alerts against auto-remediation rules and dispatches actions.
type Engine struct {
	store *store.Store
	log   zerolog.Logger
}

// New creates a new auto-remediation Engine.
func New(st *store.Store, log zerolog.Logger) *Engine {
	return &Engine{store: st, log: log.With().Str("component", "auto-remediate").Logger()}
}

// Evaluate is called synchronously after an alert is persisted.
func (e *Engine) Evaluate(ctx context.Context, alert *models.Alert) {
	rules, err := e.store.ListAutoRemediationRules(ctx, alert.TenantID)
	if err != nil || len(rules) == 0 {
		return
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if int(alert.Severity) < r.MinSeverity {
			continue
		}
		matched := false
		switch r.TriggerType {
		case "rule_id":
			matched = alert.RuleID == r.TriggerValue
		case "mitre_id":
			for _, m := range alert.MitreIDs {
				if m == r.TriggerValue {
					matched = true
					break
				}
			}
		case "severity":
			matched = true // min_severity already checked above
		}
		if !matched {
			continue
		}
		e.log.Warn().
			Str("rule", r.Name).
			Str("action", r.Action).
			Str("alert_id", alert.ID).
			Msg("auto-remediation triggered")
		go e.execute(context.Background(), r, alert)
	}
}

func (e *Engine) execute(ctx context.Context, rule models.AutoRemediationRule, alert *models.Alert) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	note := fmt.Sprintf("Auto-remediation rule '%s' triggered action '%s' for alert %s", rule.Name, rule.Action, alert.ID)
	e.log.Info().Str("note", note).Msg("auto-remediation executed")
	// Actual isolation/kill is triggered via the live-response or playbook subsystem.
	// Here we record intent; the operator can wire real actions through playbooks.
}
