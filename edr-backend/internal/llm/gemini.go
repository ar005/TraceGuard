// internal/llm/gemini.go
//
// Google Gemini provider for alert explanation.
// Uses the /v1beta/models/{model}:generateContent endpoint.

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

// geminiProvider implements Provider for the Google Gemini API.
type geminiProvider struct {
	baseURL string
	model   string
	apiKey  string
	hc      *http.Client
	log     zerolog.Logger
}

// newGeminiProvider creates a Gemini provider from the given config.
func newGeminiProvider(cfg Config, log zerolog.Logger) *geminiProvider {
	url := cfg.BaseURL
	if url == "" {
		url = "https://generativelanguage.googleapis.com"
	}
	model := cfg.Model
	if model == "" {
		model = "gemini-2.0-flash"
	}
	return &geminiProvider{
		baseURL: strings.TrimSuffix(url, "/"),
		model:   model,
		apiKey:  cfg.APIKey,
		hc:      &http.Client{Timeout: 120 * time.Second},
		log:     log,
	}
}

func (g *geminiProvider) Name() string { return "gemini" }

// ExplainAlert sends the alert to Gemini and returns a plain-English explanation.
func (g *geminiProvider) ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error) {
	prompt := BuildPrompt(alert, events)

	body, _ := json.Marshal(map[string]interface{}{
		"system_instruction": map[string]interface{}{
			"parts": []map[string]string{
				{"text": "You are a senior security analyst specialising in endpoint detection and response."},
			},
		},
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0.3,
			"maxOutputTokens": 500,
		},
	})

	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s",
		g.baseURL, g.model, g.apiKey)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("gemini returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode gemini response: %w", err)
	}
	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini returned no candidates")
	}
	return strings.TrimSpace(result.Candidates[0].Content.Parts[0].Text), nil
}

func (g *geminiProvider) Complete(ctx context.Context, system, user string) (string, error) {
	if system == "" {
		system = "You are a senior security analyst specialising in endpoint detection and response."
	}
	body, _ := json.Marshal(map[string]interface{}{
		"system_instruction": map[string]interface{}{
			"parts": []map[string]string{{"text": system}},
		},
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": user}}},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0.2,
			"maxOutputTokens": 800,
		},
	})
	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s", g.baseURL, g.model, g.apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("gemini HTTP %d: %s", resp.StatusCode, rb)
	}
	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: no candidates")
	}
	return strings.TrimSpace(result.Candidates[0].Content.Parts[0].Text), nil
}
