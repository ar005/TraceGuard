// internal/llm/openai.go
//
// OpenAI-compatible provider (works with ChatGPT and any OpenAI-compatible API).
// Uses the /v1/chat/completions endpoint.

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

// openAIProvider implements Provider for the OpenAI Chat Completions API.
type openAIProvider struct {
	baseURL string
	model   string
	apiKey  string
	hc      *http.Client
	log     zerolog.Logger
}

// newOpenAIProvider creates an OpenAI provider from the given config.
func newOpenAIProvider(cfg Config, log zerolog.Logger) *openAIProvider {
	url := cfg.BaseURL
	if url == "" {
		url = "https://api.openai.com/v1"
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o"
	}
	return &openAIProvider{
		baseURL: strings.TrimSuffix(url, "/"),
		model:   model,
		apiKey:  cfg.APIKey,
		hc:      &http.Client{Timeout: 120 * time.Second},
		log:     log,
	}
}

func (o *openAIProvider) Name() string { return "openai" }

// ExplainAlert sends the alert to OpenAI and returns a plain-English explanation.
func (o *openAIProvider) ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error) {
	prompt := BuildPrompt(alert, events)

	body, _ := json.Marshal(map[string]interface{}{
		"model": o.model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a senior security analyst specialising in endpoint detection and response."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  500,
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		o.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("openai returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode openai response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}
	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}
