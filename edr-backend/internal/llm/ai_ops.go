// internal/llm/ai_ops.go
//
// High-level AI operations built on top of Provider.Complete:
//   TriageAlert        — classify alert as tp/fp/needs_investigation with confidence
//   GenerateHuntQuery  — natural-language → hunt query + explanation
//   SummariseCase      — narrative summary of a case from its alerts + notes

package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/youredr/edr-backend/internal/models"
)

// TriageResult is the structured output from TriageAlert.
type TriageResult struct {
	Verdict     string   `json:"verdict"`      // true_positive|false_positive|needs_investigation
	Confidence  int      `json:"confidence"`   // 1–10
	Reasoning   string   `json:"reasoning"`
	MitreIDs    []string `json:"mitre_ids"`    // suggested MITRE ATT&CK IDs
	Recommended string   `json:"recommended"`  // brief recommended action
}

// HuntQueryResult is the output from GenerateHuntQuery.
type HuntQueryResult struct {
	Query       string `json:"query"`
	Explanation string `json:"explanation"`
}

const triageSystem = `You are a senior SOC analyst assessing EDR alerts.
Return ONLY a JSON object with this exact schema (no markdown fences):
{
  "verdict": "true_positive" | "false_positive" | "needs_investigation",
  "confidence": <integer 1-10>,
  "reasoning": "<1-3 sentences explaining why>",
  "mitre_ids": ["T1234", ...],
  "recommended": "<one-sentence recommended analyst action>"
}`

const huntSystem = `You are a security analyst assistant for an EDR platform.
The platform's hunt query language is SQL-like against an events table with columns:
  id, agent_id, hostname, event_type, timestamp, payload (JSONB), severity, rule_id, alert_id,
  source_type, user_uid, src_ip, dst_ip, process_name, raw_log.
The payload field holds event-specific data (e.g. payload->>'comm', payload->>'path', payload->>'dst_ip').
Common event_types: PROCESS_EXEC, NET_CONNECT, NET_ACCEPT, FILE_CREATE, FILE_WRITE, FILE_DELETE,
  LOGIN_SUCCESS, LOGIN_FAILED, SUDO_EXEC, BROWSER_REQUEST, KERNEL_MODULE_LOAD, USB_CONNECT,
  MEMORY_INJECT, CRON_MODIFY, NET_DNS, NET_TLS_SNI.
Return ONLY a JSON object (no markdown fences):
{
  "query": "<valid SQL SELECT from events WHERE ...>",
  "explanation": "<1-2 sentences explaining what this query finds>"
}
Only use SELECT. No DDL, DML, or subqueries that modify data.`

// TriageAlert classifies an alert and returns structured triage output.
func (c *Client) TriageAlert(ctx context.Context, alert *models.Alert, events []models.Event) (*TriageResult, error) {
	c.mu.RLock()
	p := c.provider
	enabled := c.cfg.Enabled
	c.mu.RUnlock()
	if !enabled || p == nil {
		return nil, fmt.Errorf("LLM not enabled")
	}

	user := buildTriagePrompt(alert, events)
	raw, err := p.Complete(ctx, triageSystem, user)
	if err != nil {
		return nil, err
	}
	raw = cleanJSON(raw)
	var result TriageResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("triage parse error (%w) — raw: %s", err, truncate(raw, 200))
	}
	if result.Verdict == "" {
		result.Verdict = "needs_investigation"
	}
	if result.Confidence < 1 || result.Confidence > 10 {
		result.Confidence = 5
	}
	return &result, nil
}

// GenerateHuntQuery converts a natural-language description into a hunt query.
func (c *Client) GenerateHuntQuery(ctx context.Context, description string) (*HuntQueryResult, error) {
	c.mu.RLock()
	p := c.provider
	enabled := c.cfg.Enabled
	c.mu.RUnlock()
	if !enabled || p == nil {
		return nil, fmt.Errorf("LLM not enabled")
	}

	raw, err := p.Complete(ctx, huntSystem, "Generate a hunt query for: "+description)
	if err != nil {
		return nil, err
	}
	raw = cleanJSON(raw)
	var result HuntQueryResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("hunt query parse error (%w) — raw: %s", err, truncate(raw, 200))
	}
	return &result, nil
}

// SummariseCase generates a narrative summary from a case, its alerts, and notes.
func (c *Client) SummariseCase(ctx context.Context, cs *models.Case, alerts []models.Alert, notes []models.CaseNote) (string, error) {
	c.mu.RLock()
	p := c.provider
	enabled := c.cfg.Enabled
	c.mu.RUnlock()
	if !enabled || p == nil {
		return "", fmt.Errorf("LLM not enabled")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Case: %s\nStatus: %s\nSeverity: %s\n",
		cs.Title, cs.Status, models.SeverityLabel(cs.Severity)))
	if cs.Description != "" {
		sb.WriteString("Description: " + cs.Description + "\n")
	}
	if len(cs.MitreIDs) > 0 {
		sb.WriteString("MITRE: " + strings.Join(cs.MitreIDs, ", ") + "\n")
	}
	if len(alerts) > 0 {
		sb.WriteString(fmt.Sprintf("\nLinked alerts (%d):\n", len(alerts)))
		max := 8
		if len(alerts) < max {
			max = len(alerts)
		}
		for _, a := range alerts[:max] {
			sb.WriteString(fmt.Sprintf("  - [%s] %s on %s (rule: %s)\n",
				models.SeverityLabel(a.Severity), a.Title, a.Hostname, a.RuleName))
		}
	}
	if len(notes) > 0 {
		sb.WriteString("\nAnalyst notes:\n")
		for _, n := range notes {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", n.CreatedAt.Format("2006-01-02"), n.Author, truncate(n.Body, 200)))
		}
	}

	system := "You are a senior SOC analyst. Write a concise investigation narrative (3-5 sentences) for this case. Cover: what happened, affected assets, likely attack stage, and recommended next steps."
	return p.Complete(ctx, system, sb.String())
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildTriagePrompt(alert *models.Alert, events []models.Event) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Alert: %s\nSeverity: %s\nHost: %s\nRule: %s\nMITRE: %s\nHit count: %d\n",
		alert.Title,
		models.SeverityLabel(alert.Severity),
		alert.Hostname,
		alert.RuleName,
		strings.Join(alert.MitreIDs, ", "),
		alert.HitCount,
	))
	if len(events) > 0 {
		sb.WriteString("Events:\n")
		max := 5
		if len(events) < max {
			max = len(events)
		}
		for _, ev := range events[:max] {
			sb.WriteString(fmt.Sprintf("  %s on %s\n", ev.EventType, ev.Timestamp.Format("15:04:05")))
		}
	}
	return sb.String()
}

// cleanJSON strips markdown code fences from LLM output before JSON parsing.
func cleanJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	// find first { and last } to tolerate surrounding prose
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		s = s[start : end+1]
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
