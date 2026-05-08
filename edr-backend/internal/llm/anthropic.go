// internal/llm/anthropic.go
//
// Anthropic/Claude provider for alert explanation.
// Uses the /v1/messages endpoint.

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// anthropicProvider implements Provider for the Anthropic Messages API.
type anthropicProvider struct {
	baseURL string
	model   string
	apiKey  string
	hc      *http.Client
	log     zerolog.Logger
}

// newAnthropicProvider creates an Anthropic provider from the given config.
func newAnthropicProvider(cfg Config, log zerolog.Logger) *anthropicProvider {
	url := cfg.BaseURL
	if url == "" {
		url = "https://api.anthropic.com"
	}
	model := cfg.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &anthropicProvider{
		baseURL: strings.TrimSuffix(url, "/"),
		model:   model,
		apiKey:  cfg.APIKey,
		hc:      &http.Client{Timeout: 120 * time.Second},
		log:     log,
	}
}

func (a *anthropicProvider) Name() string { return "anthropic" }

// ExplainAlert sends the alert to Anthropic and returns a plain-English explanation.
func (a *anthropicProvider) ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error) {
	prompt := BuildPrompt(alert, events)

	body, _ := json.Marshal(map[string]interface{}{
		"model": a.model,
		"system": "You are a senior security analyst specialising in endpoint detection and response.",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  500,
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		a.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("anthropic returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode anthropic response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("anthropic returned no content blocks")
	}
	return strings.TrimSpace(result.Content[0].Text), nil
}

func (a *anthropicProvider) Complete(ctx context.Context, system, user string) (string, error) {
	if system == "" {
		system = "You are a senior security analyst specialising in endpoint detection and response."
	}
	body, _ := json.Marshal(map[string]interface{}{
		"model":  a.model,
		"system": system,
		"messages": []map[string]string{
			{"role": "user", "content": user},
		},
		"temperature": 0.2,
		"max_tokens":  800,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("anthropic HTTP %d: %s", resp.StatusCode, rb)
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("anthropic: no content")
	}
	return strings.TrimSpace(result.Content[0].Text), nil
}
