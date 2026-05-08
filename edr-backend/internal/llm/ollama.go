// internal/llm/ollama.go
//
// Ollama LLM provider for alert explanation.
// Uses the /api/generate endpoint of the Ollama server.

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// ollamaProvider implements Provider for the Ollama API.
type ollamaProvider struct {
	baseURL string
	model   string
	hc      *http.Client
	log     zerolog.Logger
}

// newOllamaProvider creates an Ollama provider from the given config.
func newOllamaProvider(cfg Config, log zerolog.Logger) *ollamaProvider {
	url := cfg.BaseURL
	if url == "" {
		url = "http://localhost:11434"
	}
	model := cfg.Model
	if model == "" {
		model = "llama3.2"
	}
	return &ollamaProvider{
		baseURL: strings.TrimSuffix(url, "/"),
		model:   model,
		hc:      safeLLMHTTPClient(120 * time.Second),
		log:     log,
	}
}

func (o *ollamaProvider) Name() string { return "ollama" }

// ExplainAlert sends the alert to Ollama and returns a plain-English explanation.
func (o *ollamaProvider) ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error) {
	prompt := BuildPrompt(alert, events)
	return o.generate(ctx, prompt)
}

func (o *ollamaProvider) Complete(ctx context.Context, system, user string) (string, error) {
	prompt := user
	if system != "" {
		prompt = "SYSTEM: " + system + "\n\nUSER: " + user
	}
	return o.generate(ctx, prompt)
}

// generate calls the Ollama /api/generate endpoint.
func (o *ollamaProvider) generate(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":  o.model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 400,
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		o.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.hc.Do(req)
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
