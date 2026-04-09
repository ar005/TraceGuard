// internal/llm/provider.go
//
// Provider interface and shared prompt-building logic for all LLM backends.

package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/youredr/edr-backend/internal/models"
)

// Provider is the interface all LLM backends must implement.
type Provider interface {
	Name() string
	ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error)
}

// Config holds provider-agnostic LLM settings loaded from the database.
type Config struct {
	Provider string `json:"provider"` // "ollama", "openai", "anthropic", "gemini"
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
	Enabled  bool   `json:"enabled"`
}

// BuildPrompt constructs the shared prompt used by all providers.
func BuildPrompt(alert *models.Alert, events []models.Event) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"You are a security analyst assistant. Explain this EDR alert in plain English.\n\n"+
			"Alert: %s\nSeverity: %s\nHost: %s\nMITRE: %s\nFirst seen: %s\n\n",
		alert.Title,
		models.SeverityLabel(alert.Severity),
		alert.Hostname,
		strings.Join(alert.MitreIDs, ", "),
		alert.FirstSeen.Format("2006-01-02 15:04:05 UTC"),
	))

	if len(events) > 0 {
		sb.WriteString("Triggering events:\n")
		max := 5
		if len(events) < max {
			max = len(events)
		}
		for _, ev := range events[:max] {
			var p map[string]interface{}
			_ = json.Unmarshal(ev.Payload, &p)
			summary := SummarisePayload(ev.EventType, p)
			sb.WriteString(fmt.Sprintf("  - [%s] %s\n", ev.EventType, summary))
		}
	}

	sb.WriteString("\nIn 3-5 sentences:\n" +
		"1. What likely happened?\n" +
		"2. What is the attacker trying to achieve?\n" +
		"3. What should the analyst check next?\n" +
		"Keep the response concise and technical. Do not include disclaimers.")

	return sb.String()
}

// SummarisePayload extracts a human-readable summary from an event payload.
func SummarisePayload(evType string, p map[string]interface{}) string {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := p[k]; ok {
				return fmt.Sprintf("%v", v)
			}
			// Try nested: "process.comm"
			parts := strings.SplitN(k, ".", 2)
			if len(parts) == 2 {
				if sub, ok := p[parts[0]].(map[string]interface{}); ok {
					if v, ok := sub[parts[1]]; ok {
						return fmt.Sprintf("%v", v)
					}
				}
			}
		}
		return ""
	}
	switch {
	case strings.HasPrefix(evType, "FILE"):
		return get("path", "filename")
	case strings.HasPrefix(evType, "NET"):
		dst := get("dst_ip", "resolved_domain")
		port := get("dst_port")
		if port != "" {
			return dst + ":" + port
		}
		return dst
	case strings.HasPrefix(evType, "PROCESS"), strings.HasPrefix(evType, "CMD"):
		cmdline := get("cmdline", "process.cmdline", "process.comm", "comm")
		if len(cmdline) > 120 {
			cmdline = cmdline[:120] + "…"
		}
		return cmdline
	default:
		return evType
	}
}
