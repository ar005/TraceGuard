// internal/autocase/policy.go
//
// AutoCaseManager automatically creates cases from alerts that match a policy
// (min_severity, optional rule_id or mitre_id filters). One case per alert.

package autocase

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

type AutoCaseStore interface {
	ListAutoCasePolicies(ctx context.Context, tenantID string) ([]models.AutoCasePolicy, error)
	CreateCase(ctx context.Context, c *models.Case) error
	LinkAlertToCase(ctx context.Context, caseID, alertID, linkedBy string) error
}

type Manager struct {
	store AutoCaseStore
	log   zerolog.Logger
}

func New(st *store.Store, log zerolog.Logger) *Manager {
	return &Manager{
		store: st,
		log:   log.With().Str("component", "auto-case").Logger(),
	}
}

// Evaluate checks the alert against all enabled tenant policies and creates a
// case if any policy matches. At most one case is created per alert.
func (m *Manager) Evaluate(ctx context.Context, alert *models.Alert) {
	policies, err := m.store.ListAutoCasePolicies(ctx, alert.TenantID)
	if err != nil {
		m.log.Warn().Err(err).Str("tenant", alert.TenantID).Msg("list auto-case policies failed")
		return
	}

	for _, p := range policies {
		if !m.matches(alert, p) {
			continue
		}
		c := &models.Case{
			TenantID:    alert.TenantID,
			Title:       "Auto: " + alert.Title,
			Description: fmt.Sprintf("Auto-created from alert %s (severity %s)", alert.ID, severityStr(alert.Severity)),
			Severity:    alert.Severity,
			Status:      models.CaseStatusOpen,
			CreatedBy:   "auto-case",
			MitreIDs:    alert.MitreIDs,
		}
		if err := m.store.CreateCase(ctx, c); err != nil {
			m.log.Warn().Err(err).Str("alert_id", alert.ID).Msg("auto-create case failed")
			continue
		}
		if err := m.store.LinkAlertToCase(ctx, c.ID, alert.ID, "auto-case"); err != nil {
			m.log.Warn().Err(err).Str("case_id", c.ID).Msg("auto-link alert failed")
		}
		m.log.Info().Str("case_id", c.ID).Str("alert_id", alert.ID).Str("policy", p.Name).Msg("auto case created")
		return
	}
}

func (m *Manager) matches(alert *models.Alert, p models.AutoCasePolicy) bool {
	if alert.Severity < p.MinSeverity {
		return false
	}
	if len(p.RuleIDs) > 0 {
		matched := false
		for _, rid := range p.RuleIDs {
			if rid == alert.RuleID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(p.MitreIDs) > 0 {
		for _, mid := range p.MitreIDs {
			for _, amid := range alert.MitreIDs {
				if mid == amid {
					return true
				}
			}
		}
		return false
	}
	return true
}

func severityStr(s int16) string {
	switch s {
	case 1:
		return "Info"
	case 2:
		return "Low"
	case 3:
		return "Medium"
	case 4:
		return "High"
	case 5:
		return "Critical"
	default:
		return "Unknown"
	}
}
