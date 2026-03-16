// internal/detection/engine.go
// Real-time detection engine.
// Supports two rule types:
//   "match"     — fires when a single event satisfies all conditions (original behaviour)
//   "threshold" — fires when N matching events occur within a sliding time window,
//                 grouped by a configurable key (agent_id, dst_ip, process.pid, etc.)
//
// Threshold implementation uses an in-memory sliding window per (rule_id, group_key).
// Windows are pruned lazily on each event. No external state store needed.

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

// windowKey identifies a sliding window for threshold rules.
type windowKey struct {
	ruleID   string
	groupVal string
}

// Engine evaluates rules against events in real time.
type Engine struct {
	store        *store.Store
	log          zerolog.Logger
	mu           sync.RWMutex
	rules        []models.Rule
	suppressions []models.SuppressionRule
	onAlert      AlertCallback
	reCache      map[string]*regexp.Regexp

	// Threshold sliding windows: windowKey → ordered list of event timestamps.
	// Protected by winMu — separate lock to avoid holding the rule lock while
	// doing window arithmetic.
	winMu   sync.Mutex
	windows map[windowKey][]time.Time
}

// New creates a detection Engine. Call Reload() to load rules from DB.
func New(st *store.Store, log zerolog.Logger, onAlert AlertCallback) *Engine {
	e := &Engine{
		store:   st,
		log:     log.With().Str("component", "detection").Logger(),
		onAlert: onAlert,
		reCache: map[string]*regexp.Regexp{},
		windows: make(map[windowKey][]time.Time),
	}
	// Prune stale windows every 5 minutes to prevent unbounded memory growth.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			e.pruneAllWindows()
		}
	}()
	return e
}

// Reload refreshes the rule and suppression cache from the database.
func (e *Engine) Reload(ctx context.Context) error {
	rules, err := e.store.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	sups, err := e.store.ListSuppressions(ctx)
	if err != nil {
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

	// Check suppressions first.
	for i := range sups {
		s := &sups[i]
		if !s.Enabled { continue }
		if !matchesEventType(s.EventTypes, ev.EventType) { continue }
		var conds []models.RuleCondition
		if err := json.Unmarshal(s.Conditions, &conds); err != nil { continue }
		if e.matchesAll(payload, conds) {
			e.log.Debug().Str("suppression", s.ID).Str("event", ev.ID).Msg("event suppressed")
			go func(sid string) { _ = e.store.IncrSuppressionHits(context.Background(), sid) }(s.ID)
			return
		}
	}

	// Evaluate detection rules.
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled { continue }
		if !matchesEventType(rule.EventTypes, ev.EventType) { continue }
		var conditions []models.RuleCondition
		if err := json.Unmarshal(rule.Conditions, &conditions); err != nil {
			e.log.Warn().Str("rule", rule.ID).Err(err).Msg("invalid rule conditions")
			continue
		}
		if !e.matchesAll(payload, conditions) { continue }

		switch rule.RuleType {
		case "threshold":
			e.evaluateThreshold(ctx, ev, rule, payload)
		default: // "match" or empty
			e.fireAlert(ctx, ev, rule)
		}
	}
}

// ─── Threshold evaluation ─────────────────────────────────────────────────────

// evaluateThreshold maintains a per-(rule,groupKey) sliding window.
// When the window fills to threshold_count within threshold_window_s seconds, it fires.
func (e *Engine) evaluateThreshold(ctx context.Context, ev *models.Event, rule *models.Rule, payload map[string]interface{}) {
	if rule.ThresholdCount <= 0 || rule.ThresholdWindowS <= 0 {
		// Misconfigured — fall back to match behaviour
		e.fireAlert(ctx, ev, rule)
		return
	}

	// Resolve the group-by key value from the event payload or base fields.
	groupVal := e.resolveGroupKey(ev, payload, rule.GroupBy)
	key := windowKey{ruleID: rule.ID, groupVal: groupVal}
	window := time.Duration(rule.ThresholdWindowS) * time.Second
	now := time.Now()
	cutoff := now.Add(-window)

	e.winMu.Lock()
	// Append this event's timestamp.
	ts := e.windows[key]
	ts = append(ts, now)
	// Prune entries outside the window (sliding window eviction).
	start := 0
	for start < len(ts) && ts[start].Before(cutoff) {
		start++
	}
	ts = ts[start:]
	e.windows[key] = ts
	count := len(ts)
	e.winMu.Unlock()

	e.log.Debug().
		Str("rule", rule.Name).
		Str("group", groupVal).
		Int("count", count).
		Int("threshold", rule.ThresholdCount).
		Int("window_s", rule.ThresholdWindowS).
		Msg("threshold window tick")

	if count >= rule.ThresholdCount {
		// Reset window so we don't fire on every subsequent event.
		e.winMu.Lock()
		delete(e.windows, key)
		e.winMu.Unlock()

		// Build a synthetic event with threshold context for the alert.
		thresholdEv := *ev // copy
		e.log.Warn().
			Str("rule", rule.Name).
			Str("group_by", rule.GroupBy).
			Str("group_val", groupVal).
			Int("count", count).
			Int("window_s", rule.ThresholdWindowS).
			Str("agent", ev.Hostname).
			Msg("threshold rule fired")
		e.fireAlertWithContext(ctx, &thresholdEv, rule,
			fmt.Sprintf("%d events in %ds (group: %s=%s)", count, rule.ThresholdWindowS, rule.GroupBy, groupVal))
	}
}

// resolveGroupKey extracts the group-by value from the event.
// Supports: "agent_id", "hostname", and any flat payload key (e.g. "dst_ip", "process.pid").
func (e *Engine) resolveGroupKey(ev *models.Event, payload map[string]interface{}, groupBy string) string {
	switch groupBy {
	case "agent_id":
		return ev.AgentID
	case "hostname":
		return ev.Hostname
	case "event_type":
		return ev.EventType
	default:
		if v, ok := payload[groupBy]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ev.AgentID // fallback
	}
}

// pruneAllWindows removes window entries older than their respective rule windows.
// Called every 5 minutes to prevent unbounded map growth.
func (e *Engine) pruneAllWindows() {
	e.mu.RLock()
	ruleWindows := make(map[string]time.Duration)
	for _, r := range e.rules {
		if r.RuleType == "threshold" && r.ThresholdWindowS > 0 {
			ruleWindows[r.ID] = time.Duration(r.ThresholdWindowS) * time.Second
		}
	}
	e.mu.RUnlock()

	now := time.Now()
	e.winMu.Lock()
	defer e.winMu.Unlock()
	for k, ts := range e.windows {
		win, ok := ruleWindows[k.ruleID]
		if !ok {
			// Rule deleted or no longer threshold — remove window
			delete(e.windows, k)
			continue
		}
		cutoff := now.Add(-win)
		start := 0
		for start < len(ts) && ts[start].Before(cutoff) {
			start++
		}
		if start == len(ts) {
			delete(e.windows, k)
		} else {
			e.windows[k] = ts[start:]
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
	if payload == nil { return nil }

	var fired []*models.Alert
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled { continue }
		if !matchesEventType(rule.EventTypes, ev.EventType) { continue }
		var conditions []models.RuleCondition
		if err := json.Unmarshal(rule.Conditions, &conditions); err != nil { continue }
		if e.matchesAll(payload, conditions) {
			fired = append(fired, &models.Alert{
				ID: "alert-" + uuid.New().String(),
				Title: rule.Name, Description: rule.Description,
				Severity: rule.Severity, Status: "OPEN",
				RuleID: rule.ID, RuleName: rule.Name,
				MitreIDs: rule.MitreIDs, EventIDs: []string{ev.ID},
				AgentID: ev.AgentID, Hostname: ev.Hostname,
				FirstSeen: time.Now(), LastSeen: time.Now(),
			})
		}
	}
	return fired
}

// matchesAll returns true only if all conditions are satisfied.
func (e *Engine) matchesAll(payload map[string]interface{}, conds []models.RuleCondition) bool {
	for _, c := range conds {
		if !e.matchCondition(payload, c) { return false }
	}
	return true
}

func (e *Engine) matchCondition(payload map[string]interface{}, c models.RuleCondition) bool {
	actual, ok := payload[c.Field]
	if !ok { return false }
	switch c.Op {
	case "eq":         return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", c.Value)
	case "ne":         return fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", c.Value)
	case "gt":         return toFloat64(actual) > toFloat64(c.Value)
	case "lt":         return toFloat64(actual) < toFloat64(c.Value)
	case "gte":        return toFloat64(actual) >= toFloat64(c.Value)
	case "lte":        return toFloat64(actual) <= toFloat64(c.Value)
	case "in":
		vals := toStringSlice(c.Value)
		return stringSliceContains(vals, fmt.Sprintf("%v", actual))
	case "startswith": return strings.HasPrefix(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", c.Value))
	case "contains":   return strings.Contains(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", c.Value))
	case "regex":
		pattern := fmt.Sprintf("%v", c.Value)
		re, err := e.compiledRe(pattern)
		if err != nil { return false }
		return re.MatchString(fmt.Sprintf("%v", actual))
	}
	return false
}

func (e *Engine) compiledRe(pattern string) (*regexp.Regexp, error) {
	e.mu.RLock()
	re, ok := e.reCache[pattern]
	e.mu.RUnlock()
	if ok { return re, nil }
	re, err := regexp.Compile(pattern)
	if err != nil { return nil, err }
	e.mu.Lock()
	e.reCache[pattern] = re
	e.mu.Unlock()
	return re, nil
}

// dedupeWindow controls how long an open alert stays "active" for grouping.
const dedupeWindow = 10 * time.Minute

func (e *Engine) fireAlert(ctx context.Context, ev *models.Event, rule *models.Rule) {
	e.fireAlertWithContext(ctx, ev, rule, "")
}

func (e *Engine) fireAlertWithContext(ctx context.Context, ev *models.Event, rule *models.Rule, extraCtx string) {
	// Deduplication check.
	existing, err := e.store.FindOpenAlert(ctx, rule.ID, ev.AgentID, dedupeWindow)
	if err != nil {
		e.log.Warn().Err(err).Str("rule", rule.ID).Msg("dedup check failed — firing new alert")
	} else if existing != nil {
		go func() { _ = e.store.BumpAlert(context.Background(), existing.ID, ev.ID) }()
		e.log.Debug().Str("rule", rule.Name).Str("alert", existing.ID).Msg("alert deduped — bumping existing")
		return
	}

	title := rule.Name
	desc  := rule.Description
	if extraCtx != "" {
		desc = desc + " [" + extraCtx + "]"
	}

	alertID := "alert-" + uuid.New().String()
	alert := &models.Alert{
		ID: alertID, Title: title, Description: desc,
		Severity: rule.Severity, Status: "OPEN",
		RuleID: rule.ID, RuleName: rule.Name,
		MitreIDs: rule.MitreIDs, EventIDs: []string{ev.ID},
		AgentID: ev.AgentID, Hostname: ev.Hostname,
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}

	e.log.Warn().
		Str("rule", rule.Name).Str("event_id", ev.ID).
		Str("agent", ev.Hostname).Int("severity", int(rule.Severity)).
		Msg("rule fired — new alert")

	if e.onAlert != nil { e.onAlert(ctx, alert) }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func flatMap(raw []byte) map[string]interface{} {
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil { return nil }
	dst := make(map[string]interface{})
	for k, v := range payload { dst[k] = v }
	flattenPayload(payload, "", dst)
	return dst
}

func flattenPayload(src map[string]interface{}, prefix string, dst map[string]interface{}) {
	for k, v := range src {
		key := k
		if prefix != "" { key = prefix + "." + k }
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
	case float64:   return n
	case float32:   return float64(n)
	case int:       return float64(n)
	case int64:     return float64(n)
	case json.Number:
		f, _ := n.Float64(); return f
	}
	return 0
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string: return val
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, s := range val { out = append(out, fmt.Sprintf("%v", s)) }
		return out
	}
	return nil
}

func stringSliceContains(ss []string, target string) bool {
	for _, s := range ss { if s == target { return true } }
	return false
}
