// internal/llm/client.go
//
// Thread-safe LLM client that wraps the active provider.
// Supports runtime reconfiguration via Configure().

package llm

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// privateIPBlocks lists CIDR ranges that must not be reached via user-supplied URLs.
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
		"169.254.0.0/16", "fe80::/10", // link-local / cloud metadata
		"0.0.0.0/8", "100.64.0.0/10", // carrier-grade NAT
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// validateLLMBaseURL blocks SSRF by rejecting private/internal targets.
func validateLLMBaseURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	host := u.Hostname()
	addrs, err := net.LookupHost(host)
	if err != nil {
		// DNS failure — allow (will fail at request time); don't block valid offline configs.
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, block := range privateIPBlocks {
			if block.Contains(ip) {
				return fmt.Errorf("LLM base_url must not target private/internal networks (%s resolves to %s)", host, addr)
			}
		}
	}
	return nil
}

// Client wraps the active LLM provider and supports hot-swapping.
type Client struct {
	mu       sync.RWMutex
	provider Provider
	cfg      Config
	log      zerolog.Logger
}

// New creates an LLM client. For backward compatibility it reads env vars
// (OLLAMA_ENABLED, OLLAMA_URL, OLLAMA_MODEL) and configures an Ollama provider
// if those are set. The provider can later be swapped via Configure().
func New(log zerolog.Logger) *Client {
	l := log.With().Str("component", "llm").Logger()

	url := os.Getenv("OLLAMA_URL")
	model := os.Getenv("OLLAMA_MODEL")
	if url == "" {
		url = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	enabled := os.Getenv("OLLAMA_ENABLED") == "true"

	cfg := Config{
		Provider: "ollama",
		Model:    model,
		BaseURL:  url,
		Enabled:  enabled,
	}

	c := &Client{
		cfg: cfg,
		log: l,
	}

	if enabled {
		c.provider = newOllamaProvider(cfg, l)
		l.Info().Str("provider", "ollama").Str("model", model).Msg("LLM provider initialised from env vars")
	}

	return c
}

// Enabled returns true if LLM integration is active.
func (c *Client) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.Enabled && c.provider != nil
}

// ExplainAlert delegates to the active provider.
func (c *Client) ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error) {
	c.mu.RLock()
	p := c.provider
	enabled := c.cfg.Enabled
	c.mu.RUnlock()

	if !enabled || p == nil {
		return "", fmt.Errorf("LLM not enabled — configure a provider first")
	}
	return p.ExplainAlert(ctx, alert, events)
}

// Configure hot-swaps the active LLM provider based on the given config.
// Thread-safe: can be called while ExplainAlert is running.
// The provider is always created (even if Enabled is false) so that
// the Test endpoint can verify connectivity before enabling.
func (c *Client) Configure(cfg Config) error {
	// Normalize base URL: ensure it has a scheme.
	if cfg.BaseURL != "" && !strings.Contains(cfg.BaseURL, "://") {
		cfg.BaseURL = "http://" + cfg.BaseURL
	}
	if err := validateLLMBaseURL(cfg.BaseURL); err != nil {
		return fmt.Errorf("LLM base_url rejected: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var provider Provider
	switch strings.ToLower(cfg.Provider) {
	case "openai":
		provider = newOpenAIProvider(cfg, c.log)
	case "anthropic":
		provider = newAnthropicProvider(cfg, c.log)
	case "gemini":
		provider = newGeminiProvider(cfg, c.log)
	case "ollama", "":
		provider = newOllamaProvider(cfg, c.log)
	default:
		return fmt.Errorf("unknown LLM provider: %q", cfg.Provider)
	}

	if cfg.Enabled {
		c.log.Info().
			Str("provider", cfg.Provider).
			Str("model", cfg.Model).
			Str("base_url", cfg.BaseURL).
			Msg("LLM provider configured")
	} else {
		c.log.Info().Str("provider", cfg.Provider).Msg("LLM provider configured (disabled)")
	}

	c.cfg = cfg
	c.provider = provider
	return nil
}

// GetConfig returns the current configuration with the API key masked.
func (c *Client) GetConfig() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()

	masked := c.cfg
	if len(masked.APIKey) > 4 {
		masked.APIKey = "****" + masked.APIKey[len(masked.APIKey)-4:]
	} else if masked.APIKey != "" {
		masked.APIKey = "****"
	}
	return masked
}

// TestConnection sends a dummy request to the configured provider, ignoring
// the Enabled flag. Used by the /settings/llm/test endpoint so users can
// verify connectivity before flipping the switch.
func (c *Client) TestConnection(ctx context.Context) (string, error) {
	c.mu.RLock()
	p := c.provider
	c.mu.RUnlock()

	if p == nil {
		return "", fmt.Errorf("no AI provider configured — save settings first")
	}

	testAlert := &models.Alert{
		Title:    "Test Alert — Connection Check",
		Hostname: "test-host",
		Severity: 2,
		RuleName: "test-rule",
	}
	return p.ExplainAlert(ctx, testAlert, nil)
}

// ProviderName returns the name of the active provider, or "" if none.
func (c *Client) ProviderName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.provider != nil {
		return c.provider.Name()
	}
	return ""
}

// ModelName returns the configured model name.
func (c *Client) ModelName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.Model
}
