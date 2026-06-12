// internal/workers/sla_checker.go
//
// Checks SLA policy compliance every 5 minutes.
// For each tenant with enabled policies, scans open alerts that have
// exceeded MTTA or MTTR targets and records a row in sla_breaches.
// The unique index on (alert_id, metric_type) prevents duplicate breach records.

package workers

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// slaCheckerStore is the narrow interface the worker needs.
type slaCheckerStore interface {
	ListTenantsWithSLAPolicies(ctx context.Context) ([]string, error)
	GetEnabledSLAPolicies(ctx context.Context, tenantID string) ([]models.SLAPolicy, error)
	FindOpenAlertsBreachingSLA(ctx context.Context, tenantID string, mttaMinutes, mttrMinutes int) ([]models.Alert, error)
	RecordSLABreach(ctx context.Context, b *models.SLABreach) error
}

// SLAChecker runs periodic SLA compliance checks.
type SLAChecker struct {
	store    slaCheckerStore
	log      zerolog.Logger
	interval time.Duration
	stop     chan struct{}
}

// NewSLAChecker creates a new SLA checker. Interval defaults to 5 minutes.
func NewSLAChecker(store slaCheckerStore, log zerolog.Logger, interval time.Duration) *SLAChecker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &SLAChecker{
		store:    store,
		log:      log.With().Str("worker", "sla_checker").Logger(),
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Start runs the SLA checker in the background. Call Stop() to shut it down.
func (c *SLAChecker) Start(ctx context.Context) {
	go c.run(ctx)
}

// Stop signals the worker to exit.
func (c *SLAChecker) Stop() {
	close(c.stop)
}

func (c *SLAChecker) run(ctx context.Context) {
	// Run once immediately on startup, then on the ticker.
	c.check(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.check(ctx)
		case <-c.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (c *SLAChecker) check(ctx context.Context) {
	tenants, err := c.store.ListTenantsWithSLAPolicies(ctx)
	if err != nil {
		c.log.Error().Err(err).Msg("failed to list tenants with SLA policies")
		return
	}
	for _, tid := range tenants {
		c.checkTenant(ctx, tid)
	}
}

func (c *SLAChecker) checkTenant(ctx context.Context, tenantID string) {
	policies, err := c.store.GetEnabledSLAPolicies(ctx, tenantID)
	if err != nil || len(policies) == 0 {
		return
	}

	// Build the most restrictive targets across all policies (or per-severity).
	// For simplicity: use the tightest non-nil target across all policies,
	// then record breach against the matching policy.
	for _, policy := range policies {
		c.checkPolicy(ctx, tenantID, policy)
	}
}

func (c *SLAChecker) checkPolicy(ctx context.Context, tenantID string, policy models.SLAPolicy) {
	// Determine effective thresholds for this policy.
	var mttaMin, mttrMin int
	if policy.TargetMTTAMinutes != nil {
		mttaMin = *policy.TargetMTTAMinutes
	}
	if policy.TargetMTTRHours != nil {
		mttrMin = int(*policy.TargetMTTRHours * 60)
	}
	if mttaMin == 0 && mttrMin == 0 {
		return
	}

	alerts, err := c.store.FindOpenAlertsBreachingSLA(ctx, tenantID, mttaMin, mttrMin)
	if err != nil {
		c.log.Error().Err(err).Str("policy_id", policy.ID).Msg("breach query failed")
		return
	}

	now := time.Now()
	for _, alert := range alerts {
		// Filter by severity if the policy targets a specific severity.
		if policy.Severity != nil && alert.Severity != *policy.Severity {
			continue
		}

		ageMinutes := now.Sub(alert.FirstSeen).Minutes()

		// Check MTTA breach.
		if mttaMin > 0 && alert.AcknowledgedAt == nil && ageMinutes > float64(mttaMin) {
			_ = c.store.RecordSLABreach(ctx, &models.SLABreach{
				ID:          uuid.New().String(),
				TenantID:    tenantID,
				PolicyID:    policy.ID,
				AlertID:     alert.ID,
				MetricType:  "mtta",
				TargetValue: float64(mttaMin),
				ActualValue: ageMinutes,
			})
		}

		// Check MTTR breach.
		if mttrMin > 0 && alert.ResolvedAt == nil && ageMinutes > float64(mttrMin) {
			_ = c.store.RecordSLABreach(ctx, &models.SLABreach{
				ID:          uuid.New().String(),
				TenantID:    tenantID,
				PolicyID:    policy.ID,
				AlertID:     alert.ID,
				MetricType:  "mttr",
				TargetValue: float64(mttrMin) / 60,
				ActualValue: ageMinutes / 60,
			})
		}
	}

	if len(alerts) > 0 {
		c.log.Info().
			Str("policy", policy.Name).
			Str("tenant_id", tenantID).
			Int("breach_candidates", len(alerts)).
			Msg("SLA check complete")
	}
}
