// internal/disruption/engine.go
//
// Autonomous Attack Disruption — evaluates disruption policies when an alert
// fires and contains matching hosts via live response. A background release
// loop auto-reverts containments after their configured window expires.

package disruption

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/liveresponse"
	"github.com/youredr/edr-backend/internal/models"
)

// Store is the DB interface required by the Engine.
type Store interface {
	ListEnabledDisruptionPolicies(ctx context.Context, tenantID string) ([]models.DisruptionPolicy, error)
	IsAgentContained(ctx context.Context, agentID string) (bool, error)
	InsertContainment(ctx context.Context, c *models.ActiveContainment) error
	MarkContainmentFailed(ctx context.Context, id, detail string) error
	ListExpiredContainments(ctx context.Context) ([]models.ActiveContainment, error)
	ReleaseContainment(ctx context.Context, id, tenantID, releasedBy, note string) error
	ListGroupsForAgent(ctx context.Context, agentID, tenantID string) ([]string, error)
}

// LiveResponder sends commands to agents via live response.
type LiveResponder interface {
	SendCommand(ctx context.Context, agentID, action string, args []string, timeoutSecs int) (*liveresponse.Result, error)
}

// Engine evaluates disruption policies and manages containment lifecycle.
type Engine struct {
	store Store
	lr    LiveResponder
	log   zerolog.Logger
}

// New creates a disruption Engine.
func New(store Store, lr LiveResponder, log zerolog.Logger) *Engine {
	return &Engine{
		store: store,
		lr:    lr,
		log:   log.With().Str("component", "disruption").Logger(),
	}
}

// OnAlert evaluates all enabled disruption policies against the incoming alert.
// Matching policies trigger autonomous host isolation. Runs synchronously so
// callers should invoke it in a goroutine.
func (e *Engine) OnAlert(ctx context.Context, alert *models.Alert) {
	if alert.AgentID == "" {
		return
	}

	policies, err := e.store.ListEnabledDisruptionPolicies(ctx, alert.TenantID)
	if err != nil {
		e.log.Warn().Err(err).Msg("list disruption policies failed")
		return
	}
	if len(policies) == 0 {
		return
	}

	// Resolve agent group memberships once (best-effort).
	agentGroups, _ := e.store.ListGroupsForAgent(ctx, alert.AgentID, alert.TenantID)

	for _, p := range policies {
		if !e.matches(p, alert, agentGroups) {
			continue
		}

		// Avoid double-containing an already-isolated host.
		if contained, _ := e.store.IsAgentContained(ctx, alert.AgentID); contained {
			e.log.Debug().
				Str("policy", p.Name).
				Str("agent", alert.AgentID).
				Msg("agent already contained — skipping")
			continue
		}

		e.contain(ctx, p, alert)
	}
}

// StartReleaseLoop starts the background goroutine that auto-releases
// expired containments. It runs until ctx is cancelled.
func (e *Engine) StartReleaseLoop(ctx context.Context) {
	go e.releaseLoop(ctx)
}

func (e *Engine) releaseLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.releaseExpired(ctx)
		}
	}
}

func (e *Engine) releaseExpired(ctx context.Context) {
	expired, err := e.store.ListExpiredContainments(ctx)
	if err != nil {
		e.log.Warn().Err(err).Msg("list expired containments failed")
		return
	}
	for _, c := range expired {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		e.release(rctx, c, "system", "auto-released after containment window expired")
		cancel()
	}
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (e *Engine) matches(p models.DisruptionPolicy, alert *models.Alert, agentGroups []string) bool {
	// Severity gate
	if alert.Severity < p.MinSeverity {
		return false
	}
	// Rule filter (any-of) — empty = any rule
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
	// Host group filter (any-of) — empty = any host
	if len(p.HostGroups) > 0 {
		matched := false
		for _, gid := range p.HostGroups {
			for _, ag := range agentGroups {
				if gid == ag {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (e *Engine) contain(ctx context.Context, p models.DisruptionPolicy, alert *models.Alert) {
	e.log.Warn().
		Str("policy", p.Name).
		Str("alert", alert.ID).
		Str("host", alert.Hostname).
		Str("action", p.Action).
		Msg("AUTONOMOUS DISRUPTION: containing host")

	var releaseAt *time.Time
	if p.AutoReleaseHours > 0 {
		t := time.Now().Add(time.Duration(p.AutoReleaseHours) * time.Hour)
		releaseAt = &t
	}

	c := &models.ActiveContainment{
		TenantID:    alert.TenantID,
		PolicyID:    p.ID,
		PolicyName:  p.Name,
		AlertID:     alert.ID,
		AgentID:     alert.AgentID,
		Hostname:    alert.Hostname,
		Action:      p.Action,
		Status:      "active",
		ReleaseAt:   releaseAt,
		ReleasedBy:  "system",
	}
	if err := e.store.InsertContainment(ctx, c); err != nil {
		e.log.Warn().Err(err).Str("policy", p.Name).Msg("insert containment record failed")
		return
	}

	// Execute the live-response action
	if err := e.execAction(ctx, p.Action, alert.AgentID); err != nil {
		e.log.Warn().Err(err).
			Str("policy", p.Name).
			Str("host", alert.Hostname).
			Msg("disruption action failed")
		_ = e.store.MarkContainmentFailed(ctx, c.ID, err.Error())
		return
	}

	e.log.Info().
		Str("policy", p.Name).
		Str("host", alert.Hostname).
		Str("containment", c.ID).
		Msg("host contained successfully")
}

func (e *Engine) release(ctx context.Context, c models.ActiveContainment, by, note string) {
	e.log.Info().
		Str("containment", c.ID).
		Str("host", c.Hostname).
		Str("by", by).
		Msg("releasing containment")

	releaseCmd := reverseAction(c.Action)
	if err := e.execAction(ctx, releaseCmd, c.AgentID); err != nil {
		e.log.Warn().Err(err).
			Str("containment", c.ID).
			Str("host", c.Hostname).
			Msg("release action failed — marking anyway")
	}

	if err := e.store.ReleaseContainment(ctx, c.ID, c.TenantID, by, note); err != nil {
		e.log.Warn().Err(err).Str("containment", c.ID).Msg("update containment status failed")
	}
}

func (e *Engine) execAction(ctx context.Context, action, agentID string) error {
	if e.lr == nil {
		return fmt.Errorf("live response not available")
	}
	_, err := e.lr.SendCommand(ctx, agentID, action, nil, 30)
	return err
}

func reverseAction(action string) string {
	switch action {
	case "isolate":
		return "release"
	default:
		return action
	}
}
