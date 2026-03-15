// internal/detection/engine.go
// Real-time detection engine.
// Evaluates each incoming event against all enabled rules.
// Checks suppression rules first; only fires an alert if no suppression matches.

package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// AlertCallback is called when a rule fires.
type AlertCallback func(ctx context.Context, alert *models.Alert)

// Engine evaluates rules against events in real time.
type Engine struct {
	store       *store.Store
	log         zerolog.Logger
	mu          sync.RWMutex
	rules       []models.Rule
	suppressions []models.SuppressionRule
	onAlert     AlertCallback
	reCache     map[string]*regexp.Regexp
}

// New creates a detection Engine. Call Reload() to load rules from DB.
func New(st *store.Store, log zerolog.Logger, onAlert AlertCallback) *Engine {
	return &Engine{
		store:   st,
		log:     log.With().Str("component", "detection").Logger(),
		onAlert: onAlert,
		reCache: map[string]*regexp.Regexp{},
	}
}

// Reload refreshes the rule and suppression cache from the database.
func (e *Engine) Reload(ctx context.Context) error {
	rules, err := e.store.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	sups, err := e.store.ListSuppressions(ctx)
	if err != nil {
		// Non-fatal: log and continue with empty suppressions
		e.log.Warn().Err(err).Msg("load suppressions failed — continuing without")
		sups = nil
	}

	e.mu.Lock()
	e.rules = rules
	e.suppressions = sups
	e.mu.Unlock()

	e.log.Info().Int("rules", len(rules)).Int("suppressions", len(sups)).Msg("rules loaded")
	return nil
}

// Evaluate checks a stored event against all loaded rules.
func (e *Engine) Evaluate(ctx context.Context, ev *models.Event) {
	e.mu.RLock()
	rules := e.rules
	sups  := e.suppressions
	e.mu.RUnlock()

	payload := flatMap(ev.Payload)
	if payload == nil {
		return
	}

	// Check suppressions first — if any match, drop event entirely.
	for i := range sups {
		s := &sups[i]
		if !s.Enabled {
			continue
		}
		if !matchesEventType(s.EventTypes, ev.EventType) {
			continue
		}
		var conds []models.RuleCondition
		if err := json.Unmarshal(s.Conditions, &conds); err != nil {
			continue
		}
		if e.matchesAll(payload, conds) {
			e.log.Debug().
				Str("suppression", s.ID).
				Str("name", s.Name).
				Str("event", ev.ID).
				Msg("event suppressed")
			// Record hit count asynchronously — don't block hot path.
			go func(sid string) {
				_ = e.store.IncrSuppressionHits(context.Background(), sid)
			}(s.ID)
			return
		}
	}

	// Evaluate detection rules.
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue
		}
		if !matchesEventType(rule.EventTypes, ev.EventType) {
			continue
		}
		var conditions []models.RuleCondition
		if err := json.Unmarshal(rule.Conditions, &conditions); err != nil {
			e.log.Warn().Str("rule", rule.ID).Err(err).Msg("invalid rule conditions")
			continue
		}
		if e.matchesAll(payload, conditions) {
			e.fireAlert(ctx, ev, rule)
		}
	}
}

// EvaluateAndCollect runs detection and returns all alerts fired (without calling onAlert).
// Used by the inject endpoint for synchronous rule-test feedback.
func (e *Engine) EvaluateAndCollect(_ context.Context, ev *models.Event) []*models.Alert {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	payload := flatMap(ev.Payload)
	if payload == nil {
		return nil
	}

	var fired []*models.Alert
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue
		}
		if !matchesEventType(rule.EventTypes, ev.EventType) {
			continue
		}
		var conditions []models.RuleCondition
		if err := json.Unmarshal(rule.Conditions, &conditions); err != nil {
			continue
		}
		if e.matchesAll(payload, conditions) {
			fired = append(fired, &models.Alert{
				ID:          "alert-" + uuid.New().String(),
				Title:       rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Status:      "OPEN",
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				MitreIDs:    rule.MitreIDs,
				EventIDs:    []string{ev.ID},
				AgentID:     ev.AgentID,
				Hostname:    ev.Hostname,
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			})
		}
	}
	return fired
}

// matchesAll returns true only if all conditions are satisfied.
func (e *Engine) matchesAll(payload map[string]interface{}, conds []models.RuleCondition) bool {
	for _, c := range conds {
		if !e.matchCondition(payload, c) {
			return false
		}
	}
	return true
}

func (e *Engine) matchCondition(payload map[string]interface{}, c models.RuleCondition) bool {
	actual, ok := payload[c.Field]
	if !ok {
		return false
	}

	switch c.Op {
	case "eq":
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", c.Value)
	case "ne":
		return fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", c.Value)
	case "gt":
		return toFloat64(actual) > toFloat64(c.Value)
	case "lt":
		return toFloat64(actual) < toFloat64(c.Value)
	case "gte":
		return toFloat64(actual) >= toFloat64(c.Value)
	case "lte":
		return toFloat64(actual) <= toFloat64(c.Value)
	case "in":
		vals := toStringSlice(c.Value)
		s := fmt.Sprintf("%v", actual)
		return stringSliceContains(vals, s)
	case "startswith":
		return strings.HasPrefix(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", c.Value))
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", c.Value))
	case "regex":
		pattern := fmt.Sprintf("%v", c.Value)
		re, err := e.compiledRe(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", actual))
	}
	return false
}

func (e *Engine) compiledRe(pattern string) (*regexp.Regexp, error) {
	e.mu.RLock()
	re, ok := e.reCache[pattern]
	e.mu.RUnlock()
	if ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.reCache[pattern] = re
	e.mu.Unlock()
	return re, nil
}

func (e *Engine) fireAlert(ctx context.Context, ev *models.Event, rule *models.Rule) {
	alertID := "alert-" + uuid.New().String()
	alert := &models.Alert{
		ID:          alertID,
		Title:       rule.Name,
		Description: rule.Description,
		Severity:    rule.Severity,
		Status:      "OPEN",
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		MitreIDs:    rule.MitreIDs,
		EventIDs:    []string{ev.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Hostname,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
	}

	e.log.Warn().
		Str("rule",     rule.Name).
		Str("event_id", ev.ID).
		Str("agent",    ev.Hostname).
		Int("severity", int(rule.Severity)).
		Msg("rule fired")

	if e.onAlert != nil {
		e.onAlert(ctx, alert)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// flatMap decodes JSON payload and flattens nested keys: {"process":{"comm":"bash"}} → {"process.comm":"bash"}
func flatMap(raw []byte) map[string]interface{} {
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	dst := make(map[string]interface{})
	for k, v := range payload {
		dst[k] = v
	}
	flattenPayload(payload, "", dst)
	return dst
}

// flattenPayload converts {\"process\":{\"comm\":\"bash\"}} into {\"process.comm\":\"bash\"}.
func flattenPayload(src map[string]interface{}, prefix string, dst map[string]interface{}) {
	for k, v := range src {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			flattenPayload(val, key, dst)
		default:
			dst[key] = val
		}
	}
}

func matchesEventType(eventTypes []string, evType string) bool {
	return stringSliceContains(eventTypes, evType) || stringSliceContains(eventTypes, "*")
}

func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, s := range val {
			out = append(out, fmt.Sprintf("%v", s))
		}
		return out
	}
	return nil
}

func stringSliceContains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
