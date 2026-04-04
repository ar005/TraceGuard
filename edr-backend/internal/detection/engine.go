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
	"github.com/youredr/edr-backend/internal/liveresponse"
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

// seqKey identifies an in-progress sequence for a (rule, correlation value).
type seqKey struct {
	ruleID  string
	corrVal string
}

// seqTracker tracks progress through a sequence rule's steps.
type seqTracker struct {
	completedSteps int
	eventIDs       []string
	firstSeen      time.Time
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

	// Threshold sliding windows: windowKey �� ordered list of event timestamps.
	// Protected by winMu — separate lock to avoid holding the rule lock while
	// doing window arithmetic.
	winMu   sync.Mutex
	windows map[windowKey][]time.Time

	// Sequence tracking: seqKey → list of active trackers.
	seqMu          sync.Mutex
	sequences      map[seqKey][]*seqTracker
	parsedSeqSteps map[string][]models.SequenceStep // ruleID → parsed steps (cached on Reload)

	// IOC caches — loaded periodically from the database.
	// Each map is value → *IOC for O(1) lookup on every event.
	iocMu      sync.RWMutex
	iocIPs     map[string]*models.IOC
	iocDomains map[string]*models.IOC
	iocHashes  map[string]*models.IOC // SHA256 and MD5 combined

	// Live response manager for auto-response actions (quarantine, block_ip).
	lr *liveresponse.Manager
}

// New creates a detection Engine. Call Reload() to load rules from DB.
func New(st *store.Store, log zerolog.Logger, onAlert AlertCallback) *Engine {
	e := &Engine{
		store:          st,
		log:            log.With().Str("component", "detection").Logger(),
		onAlert:        onAlert,
		reCache:        map[string]*regexp.Regexp{},
		windows:        make(map[windowKey][]time.Time),
		sequences:      make(map[seqKey][]*seqTracker),
		parsedSeqSteps: make(map[string][]models.SequenceStep),
		iocIPs:         make(map[string]*models.IOC),
		iocDomains:     make(map[string]*models.IOC),
		iocHashes:      make(map[string]*models.IOC),
	}
	// Prune stale windows and sequences every 5 minutes.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			e.pruneAllWindows()
			e.pruneSequences()
		}
	}()
	// Refresh IOC cache every 60 seconds.
	go func() {
		// Initial load.
		e.reloadIOCs()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			e.reloadIOCs()
		}
	}()
	return e
}

// SetAutoResponder sets the live response manager used for automatic
// containment actions (quarantine files, block IPs) when IOC matches fire.
func (e *Engine) SetAutoResponder(lr *liveresponse.Manager) {
	e.lr = lr
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
	// Pre-parse sequence steps so we don't unmarshal on every event.
	parsed := make(map[string][]models.SequenceStep)
	for _, r := range rules {
		if r.RuleType == "sequence" && len(r.SequenceSteps) > 0 {
			var steps []models.SequenceStep
			if err := json.Unmarshal(r.SequenceSteps, &steps); err == nil && len(steps) >= 2 {
				parsed[r.ID] = steps
			}
		}
	}

	e.mu.Lock()
	e.rules = rules
	e.suppressions = sups
	e.parsedSeqSteps = parsed
	e.mu.Unlock()
	e.log.Info().Int("rules", len(rules)).Int("suppressions", len(sups)).Int("sequence_rules", len(parsed)).Msg("rules loaded")
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

	// Check IOC matches (IP, domain, hash).
	e.checkIOCs(ctx, ev, payload)

	// Check for typosquat / lookalike domains on browser request events.
	e.checkTyposquat(ctx, ev, payload)

	// Evaluate detection rules.
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled { continue }
		if !matchesEventType(rule.EventTypes, ev.EventType) { continue }

		// Sequence rules use per-step conditions, not global conditions.
		if rule.RuleType == "sequence" {
			e.evaluateSequence(ctx, ev, rule, payload)
			continue
		}

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

// ─── Sequence evaluation ─────────────────────────────────────────────────────

// evaluateSequence checks if an event advances or starts a sequence rule.
func (e *Engine) evaluateSequence(ctx context.Context, ev *models.Event, rule *models.Rule, payload map[string]interface{}) {
	e.mu.RLock()
	steps, ok := e.parsedSeqSteps[rule.ID]
	e.mu.RUnlock()
	if !ok || len(steps) < 2 {
		return
	}

	window := time.Duration(rule.SequenceWindowS) * time.Second
	if window <= 0 {
		window = 30 * time.Second
	}
	corrVal := e.resolveGroupKey(ev, payload, rule.SequenceBy)
	key := seqKey{ruleID: rule.ID, corrVal: corrVal}
	now := time.Now()

	e.seqMu.Lock()
	defer e.seqMu.Unlock()

	trackers := e.sequences[key]

	// Prune expired trackers.
	alive := trackers[:0]
	for _, t := range trackers {
		if now.Sub(t.firstSeen) <= window {
			alive = append(alive, t)
		}
	}

	// Check if this event advances any existing tracker to its next step.
	for i := len(alive) - 1; i >= 0; i-- {
		t := alive[i]
		nextIdx := t.completedSteps
		if nextIdx >= len(steps) {
			continue
		}

		step := steps[nextIdx]
		if !matchesEventType(step.EventTypes, ev.EventType) {
			continue
		}
		if !e.matchesAll(payload, step.Conditions) {
			continue
		}

		// Event matches the next expected step.
		t.completedSteps++
		t.eventIDs = append(t.eventIDs, ev.ID)

		// Check if the sequence is now complete.
		if t.completedSteps >= len(steps) {
			e.fireSequenceAlert(ctx, ev, rule, t, steps)
			alive = append(alive[:i], alive[i+1:]...)
		}
	}

	// Check if this event matches step 0 (start of a NEW sequence).
	step0 := steps[0]
	if matchesEventType(step0.EventTypes, ev.EventType) && e.matchesAll(payload, step0.Conditions) {
		alive = append(alive, &seqTracker{
			completedSteps: 1,
			eventIDs:       []string{ev.ID},
			firstSeen:      now,
		})
	}

	// Cap tracker count per key to prevent memory abuse.
	const maxTrackersPerKey = 100
	if len(alive) > maxTrackersPerKey {
		alive = alive[len(alive)-maxTrackersPerKey:]
	}

	if len(alive) == 0 {
		delete(e.sequences, key)
	} else {
		e.sequences[key] = alive
	}
}

// fireSequenceAlert creates an alert when all steps of a sequence rule are satisfied.
func (e *Engine) fireSequenceAlert(ctx context.Context, ev *models.Event, rule *models.Rule, t *seqTracker, steps []models.SequenceStep) {
	// Build step labels for the description.
	var stepDescs []string
	for i, s := range steps {
		label := s.Label
		if label == "" {
			label = fmt.Sprintf("step %d", i+1)
		}
		stepDescs = append(stepDescs, label)
	}
	seqDesc := strings.Join(stepDescs, " → ")

	extraCtx := fmt.Sprintf("sequence: %s | %d events in %ds window, correlated by %s",
		seqDesc, len(t.eventIDs), rule.SequenceWindowS, rule.SequenceBy)

	// Deduplication check.
	existing, err := e.store.FindOpenAlert(ctx, rule.ID, ev.AgentID, dedupeWindow)
	if err == nil && existing != nil {
		go func() {
			for _, eid := range t.eventIDs {
				_ = e.store.BumpAlert(context.Background(), existing.ID, eid)
			}
		}()
		e.log.Debug().Str("rule", rule.Name).Str("alert", existing.ID).Msg("sequence alert deduped")
		return
	}

	alertID := "alert-" + uuid.New().String()
	alert := &models.Alert{
		ID: alertID, Title: rule.Name, Description: rule.Description + " [" + extraCtx + "]",
		Severity: rule.Severity, Status: "OPEN",
		RuleID: rule.ID, RuleName: rule.Name,
		MitreIDs: rule.MitreIDs, EventIDs: t.eventIDs,
		AgentID: ev.AgentID, Hostname: ev.Hostname,
		FirstSeen: t.firstSeen, LastSeen: time.Now(),
	}

	e.log.Warn().
		Str("rule", rule.Name).
		Strs("event_ids", t.eventIDs).
		Int("steps", len(steps)).
		Str("agent", ev.Hostname).
		Msg("sequence rule fired — new alert")

	if e.onAlert != nil {
		e.onAlert(ctx, alert)
	}
}

// pruneSequences removes expired sequence trackers.
func (e *Engine) pruneSequences() {
	e.mu.RLock()
	seqWindows := make(map[string]time.Duration)
	for _, r := range e.rules {
		if r.RuleType == "sequence" && r.SequenceWindowS > 0 {
			seqWindows[r.ID] = time.Duration(r.SequenceWindowS) * time.Second
		}
	}
	e.mu.RUnlock()

	now := time.Now()
	e.seqMu.Lock()
	defer e.seqMu.Unlock()
	for k, trackers := range e.sequences {
		win, ok := seqWindows[k.ruleID]
		if !ok {
			delete(e.sequences, k)
			continue
		}
		alive := trackers[:0]
		for _, t := range trackers {
			if now.Sub(t.firstSeen) <= win {
				alive = append(alive, t)
			}
		}
		if len(alive) == 0 {
			delete(e.sequences, k)
		} else {
			e.sequences[k] = alive
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

// ─── IOC matching ─────────────────────────────────────────────────────────────

// reloadIOCs refreshes the in-memory IOC caches from the database.
func (e *Engine) reloadIOCs() {
	ctx := context.Background()
	ips, err := e.store.LoadActiveIOCs(ctx, "ip")
	if err != nil {
		e.log.Warn().Err(err).Msg("failed to load IP IOCs")
		ips = map[string]*models.IOC{}
	}
	domains, err := e.store.LoadActiveIOCs(ctx, "domain")
	if err != nil {
		e.log.Warn().Err(err).Msg("failed to load domain IOCs")
		domains = map[string]*models.IOC{}
	}
	sha256, err := e.store.LoadActiveIOCs(ctx, "hash_sha256")
	if err != nil {
		e.log.Warn().Err(err).Msg("failed to load hash_sha256 IOCs")
		sha256 = map[string]*models.IOC{}
	}
	md5, err := e.store.LoadActiveIOCs(ctx, "hash_md5")
	if err != nil {
		e.log.Warn().Err(err).Msg("failed to load hash_md5 IOCs")
		md5 = map[string]*models.IOC{}
	}
	// Merge MD5 hashes into the same map.
	hashes := sha256
	for k, v := range md5 {
		hashes[k] = v
	}

	e.iocMu.Lock()
	e.iocIPs = ips
	e.iocDomains = domains
	e.iocHashes = hashes
	e.iocMu.Unlock()

	total := len(ips) + len(domains) + len(hashes)
	if total > 0 {
		e.log.Info().
			Int("ips", len(ips)).Int("domains", len(domains)).Int("hashes", len(hashes)).
			Msg("IOC cache refreshed")
	}
}

// checkIOCs matches an event against the IOC cache and fires alerts for hits.
func (e *Engine) checkIOCs(ctx context.Context, ev *models.Event, payload map[string]interface{}) {
	e.iocMu.RLock()
	ips := e.iocIPs
	domains := e.iocDomains
	hashes := e.iocHashes
	e.iocMu.RUnlock()

	// Skip if no IOCs loaded.
	if len(ips) == 0 && len(domains) == 0 && len(hashes) == 0 {
		return
	}

	// Check IP IOCs against network events.
	if len(ips) > 0 {
		for _, field := range []string{"dst_ip", "src_ip"} {
			if v, ok := payload[field]; ok {
				ip := strings.ToLower(fmt.Sprintf("%v", v))
				if ioc, hit := ips[ip]; hit {
					e.fireIOCAlert(ctx, ev, ioc, field, ip)
					// Auto-block: instruct agent to block the matched IP.
					go e.autoBlockIP(ctx, ev.AgentID, ip)
				}
			}
		}
	}

	// Check domain IOCs against DNS events.
	if len(domains) > 0 {
		for _, field := range []string{"dns_query", "resolved_domain", "query"} {
			if v, ok := payload[field]; ok {
				domain := strings.ToLower(fmt.Sprintf("%v", v))
				if ioc, hit := domains[domain]; hit {
					e.fireIOCAlert(ctx, ev, ioc, field, domain)
				}
			}
		}
	}

	// Check hash IOCs against file and process exec events.
	if len(hashes) > 0 {
		for _, field := range []string{"exe_hash", "hash_after", "hash_before"} {
			if v, ok := payload[field]; ok {
				hash := strings.ToLower(fmt.Sprintf("%v", v))
				if hash == "" {
					continue
				}
				if ioc, hit := hashes[hash]; hit {
					e.fireIOCAlert(ctx, ev, ioc, field, hash)
					// Auto-quarantine: if the event has a file path, quarantine it.
					if filePath, fpOK := payload["path"]; fpOK {
						go e.autoQuarantine(ctx, ev.AgentID, fmt.Sprintf("%v", filePath))
					}
				}
			}
		}
	}
}

// fireIOCAlert creates an alert when an event matches an IOC.
func (e *Engine) fireIOCAlert(ctx context.Context, ev *models.Event, ioc *models.IOC, field, value string) {
	// Deduplication: check for existing open alert for this IOC + agent.
	ruleID := "ioc-" + ioc.ID
	existing, err := e.store.FindOpenAlert(ctx, ruleID, ev.AgentID, dedupeWindow)
	if err == nil && existing != nil {
		go func() { _ = e.store.BumpAlert(context.Background(), existing.ID, ev.ID) }()
		go func() { _ = e.store.IncrIOCHits(context.Background(), ioc.ID) }()
		return
	}

	alertID := "alert-" + uuid.New().String()
	title := fmt.Sprintf("IOC Match: %s %s", ioc.Type, ioc.Value)
	desc := fmt.Sprintf("Event field %q matched %s IOC %q (source: %s). %s",
		field, ioc.Type, ioc.Value, ioc.Source, ioc.Description)

	alert := &models.Alert{
		ID: alertID, Title: title, Description: desc,
		Severity: ioc.Severity, Status: "OPEN",
		RuleID: ruleID, RuleName: title,
		MitreIDs: []string{}, EventIDs: []string{ev.ID},
		AgentID: ev.AgentID, Hostname: ev.Hostname,
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}

	e.log.Warn().
		Str("ioc_type", ioc.Type).Str("ioc_value", ioc.Value).
		Str("field", field).Str("event_id", ev.ID).
		Str("agent", ev.Hostname).
		Msg("IOC match — alert fired")

	go func() { _ = e.store.IncrIOCHits(context.Background(), ioc.ID) }()
	if e.onAlert != nil {
		e.onAlert(ctx, alert)
	}
}

// ─── Auto-response actions ────────────────────────────────────────────────────

// autoQuarantine sends a quarantine command to the agent for a matched file.
func (e *Engine) autoQuarantine(ctx context.Context, agentID, filePath string) {
	if e.lr == nil || !e.lr.IsConnected(agentID) {
		e.log.Warn().Str("agent", agentID).Str("file", filePath).Msg("auto-quarantine skipped: agent not connected")
		return
	}
	result, err := e.lr.SendCommand(ctx, agentID, "quarantine", []string{filePath}, 30)
	if err != nil {
		e.log.Error().Err(err).Str("agent", agentID).Str("file", filePath).Msg("auto-quarantine failed")
		return
	}
	e.log.Warn().Str("agent", agentID).Str("file", filePath).Str("status", result.Status).Msg("AUTO-QUARANTINE executed")
}

// autoBlockIP sends a block_ip command to the agent for a matched IOC IP.
func (e *Engine) autoBlockIP(ctx context.Context, agentID, ip string) {
	if e.lr == nil || !e.lr.IsConnected(agentID) {
		e.log.Warn().Str("agent", agentID).Str("ip", ip).Msg("auto-block skipped: agent not connected")
		return
	}
	result, err := e.lr.SendCommand(ctx, agentID, "block_ip", []string{ip}, 30)
	if err != nil {
		e.log.Error().Err(err).Str("agent", agentID).Str("ip", ip).Msg("auto-block-ip failed")
		return
	}
	e.log.Warn().Str("agent", agentID).Str("ip", ip).Str("status", result.Status).Msg("AUTO-BLOCK-IP executed")
}

// ─── Typosquat detection ──────────────────────────────────────────────────────

// checkTyposquat looks for lookalike/typosquat domains in BROWSER_REQUEST events.
func (e *Engine) checkTyposquat(ctx context.Context, ev *models.Event, payload map[string]interface{}) {
	if ev.EventType != "BROWSER_REQUEST" {
		return
	}

	domainVal, ok := payload["domain"]
	if !ok {
		return
	}
	domainStr := strings.ToLower(fmt.Sprintf("%v", domainVal))
	if domainStr == "" {
		return
	}

	brand, dist := CheckTyposquat(domainStr)
	if brand == "" {
		return
	}

	// Deduplication: use a synthetic rule ID for typosquat alerts.
	ruleID := "typosquat-detection"
	existing, err := e.store.FindOpenAlert(ctx, ruleID, ev.AgentID, dedupeWindow)
	if err == nil && existing != nil {
		go func() { _ = e.store.BumpAlert(context.Background(), existing.ID, ev.ID) }()
		return
	}

	alertID := "alert-" + uuid.New().String()
	alert := &models.Alert{
		ID:          alertID,
		Title:       fmt.Sprintf("Typosquat Domain Detected: %s (similar to %s)", domainStr, brand),
		Description: fmt.Sprintf("User visited %s which is %d edit(s) away from %s — possible phishing/typosquatting.", domainStr, dist, brand),
		Severity:    3, // HIGH
		Status:      "OPEN",
		RuleID:      ruleID,
		RuleName:    "Typosquat Domain Detection",
		MitreIDs:    []string{"T1566.002"},
		EventIDs:    []string{ev.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Hostname,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
	}

	e.log.Warn().
		Str("domain", domainStr).Str("brand", brand).Int("distance", dist).
		Str("event_id", ev.ID).Str("agent", ev.Hostname).
		Msg("typosquat domain detected — alert fired")

	if e.onAlert != nil {
		e.onAlert(ctx, alert)
	}
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
