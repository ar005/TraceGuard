// internal/llm/ollama.go
//
// Ollama LLM client for alert explanation.
// Configured via environment variables:
//   OLLAMA_URL   — base URL of Ollama server (default: http://localhost:11434)
//   OLLAMA_MODEL — model name (default: llama3.2)
//
// The Explain() method sends the alert + triggering events to Ollama and
// returns a plain-English explanation. Results are NOT cached here —
// the caller (API handler) caches on the alert.

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// Client is an Ollama API client.
type Client struct {
	baseURL string
	model   string
	hc      *http.Client
	log     zerolog.Logger
	enabled bool
}

// New creates an Ollama client from environment variables.
// Returns a disabled client (all methods no-op) if OLLAMA_URL is unset.
func New(log zerolog.Logger) *Client {
	url   := os.Getenv("OLLAMA_URL")
	model := os.Getenv("OLLAMA_MODEL")
	if url == "" {
		url = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	enabled := os.Getenv("OLLAMA_ENABLED") == "true"
	return &Client{
		baseURL: strings.TrimSuffix(url, "/"),
		model:   model,
		hc:      &http.Client{Timeout: 120 * time.Second},
		log:     log.With().Str("component", "llm").Logger(),
		enabled: enabled,
	}
}

// Enabled returns true if Ollama integration is configured.
func (c *Client) Enabled() bool { return c.enabled }

// ExplainAlert sends an alert and its triggering events to Ollama and returns
// a plain-English explanation of what happened and what to investigate next.
func (c *Client) ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error) {
	if !c.enabled {
		return "", fmt.Errorf("ollama not enabled (set OLLAMA_ENABLED=true)")
	}

	// Build a concise prompt — don't send raw payloads (too large / privacy risk)
	// Send: rule name, severity, hostname, MITRE IDs, first 5 event types + summaries
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
		if len(events) < max { max = len(events) }
		for _, ev := range events[:max] {
			// Extract a short summary from the payload without sending full JSON
			var p map[string]interface{}
			_ = json.Unmarshal(ev.Payload, &p)
			summary := summarisePayload(ev.EventType, p)
			sb.WriteString(fmt.Sprintf("  - [%s] %s\n", ev.EventType, summary))
		}
	}

	sb.WriteString("\nIn 3-5 sentences:\n" +
		"1. What likely happened?\n" +
		"2. What is the attacker trying to achieve?\n" +
		"3. What should the analyst check next?\n" +
		"Keep the response concise and technical. Do not include disclaimers.")

	return c.generate(ctx, sb.String())
}

// generate calls the Ollama /api/generate endpoint.
func (c *Client) generate(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":  c.model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 400,
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Response string `json:"response"`
		Done     bool   `json:"done"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode ollama response: %w", err)
	}
	return strings.TrimSpace(result.Response), nil
}

// summarisePayload extracts a human-readable summary from an event payload.
func summarisePayload(evType string, p map[string]interface{}) string {
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
		if port != "" { return dst + ":" + port }
		return dst
	case strings.HasPrefix(evType, "PROCESS"), strings.HasPrefix(evType, "CMD"):
		cmdline := get("cmdline", "process.cmdline", "process.comm", "comm")
		if len(cmdline) > 120 { cmdline = cmdline[:120] + "…" }
		return cmdline
	default:
		return evType
	}
}
