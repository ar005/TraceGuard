// internal/connectors/azure.go
//
// AzureConnector — polls Azure Monitor Activity Log REST API for management
// plane events (sign-ins, resource mutations, RBAC changes, policy assignments).
//
// Auth: Azure AD service principal (client_credentials OAuth2 flow).
//   Endpoint: https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
//   Scope:    https://management.azure.com/.default
//
// OCSF mapping:
//   Microsoft.Authorization/roleAssignments/write → ClassUID 6001 (PolicyChange)
//   Microsoft.AAD/signIns/*                       → ClassUID 3002 (Authentication)
//   (other)                                       → ClassUID 4001 (CloudAPIActivity)
//
// Config stored in xdr_sources.config (JSON):
//   {
//     "tenant_id":       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//     "client_id":       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//     "client_secret":   "your-secret",
//     "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//     "poll_interval_ms": 60000
//   }

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/ocsf"
)

func init() {
	RegisterFactory("azure", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg AzureConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("azure config: %w", err)
		}
		if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("azure config: tenant_id, client_id, client_secret required")
		}
		if cfg.PollIntervalMS <= 0 {
			cfg.PollIntervalMS = 60_000
		}
		return &AzureConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "azure").Str("id", src.ID).Logger(),
		}, nil
	})
}

// AzureConfig is stored as JSON in xdr_sources.config.
type AzureConfig struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	SubscriptionID string `json:"subscription_id"`
	PollIntervalMS int    `json:"poll_interval_ms"`
}

// AzureConnector polls Azure Monitor Activity Log and emits XdrEvents.
type AzureConnector struct {
	id          string
	cfg         AzureConfig
	log         zerolog.Logger
	accessToken string
	tokenExpiry time.Time
	since       time.Time
}

func (c *AzureConnector) ID() string         { return c.id }
func (c *AzureConnector) SourceType() string { return "cloud" }

func (c *AzureConnector) Start(ctx context.Context, sink EventSink) error {
	c.since = time.Now().Add(-10 * time.Minute)

	interval := time.Duration(c.cfg.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.poll(ctx, sink); err != nil {
				c.log.Debug().Err(err).Msg("azure poll error")
			}
		}
	}
}

func (c *AzureConnector) poll(ctx context.Context, sink EventSink) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("azure token: %w", err)
	}

	filter := fmt.Sprintf("eventTimestamp ge '%s'", c.since.UTC().Format(time.RFC3339))
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$filter=%s",
		c.cfg.SubscriptionID,
		url.QueryEscape(filter),
	)

	newest := c.since
	for apiURL != "" {
		events, next, err := c.fetchActivityLogPage(ctx, token, apiURL)
		if err != nil {
			return err
		}
		for _, raw := range events {
			ev, err := parseAzureActivityLogEvent(raw, c.id)
			if err != nil {
				continue
			}
			if ev.Event.Timestamp.After(newest) {
				newest = ev.Event.Timestamp
			}
			if err := sink.Publish(ev); err != nil {
				c.log.Warn().Err(err).Msg("sink publish failed")
			}
			metrics.XdrEventsReceived.WithLabelValues("cloud").Inc()
		}
		apiURL = next
	}
	if newest.After(c.since) {
		c.since = newest
	}
	return nil
}

func (c *AzureConnector) fetchActivityLogPage(ctx context.Context, token, pageURL string) ([]json.RawMessage, string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("azure api %d: %s", resp.StatusCode, body)
	}

	var page struct {
		Value    []json.RawMessage `json:"value"`
		NextLink string            `json:"nextLink"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, "", err
	}
	return page.Value, page.NextLink, nil
}

func (c *AzureConnector) getToken(ctx context.Context) (string, error) {
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.cfg.TenantID)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("azure oauth: %s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	return c.accessToken, nil
}

func (c *AzureConnector) Health(ctx context.Context) error {
	if _, err := c.getToken(ctx); err != nil {
		return fmt.Errorf("azure health: %w", err)
	}
	return nil
}

// ── Azure Activity Log event parser ──────────────────────────────────────────

type azureActivityLogEntry struct {
	EventTimestamp  string `json:"eventTimestamp"`
	OperationName   struct{ Value string `json:"value"` } `json:"operationName"`
	Category        struct{ Value string `json:"value"` } `json:"category"`
	Status          struct{ Value string `json:"value"` } `json:"status"`
	SubStatus       struct{ Value string `json:"value"` } `json:"subStatus"`
	Caller          string `json:"caller"`
	CorrelationID   string `json:"correlationId"`
	ResourceID      string `json:"resourceId"`
	SubscriptionID  string `json:"subscriptionId"`
	Level           string `json:"level"`
	Description     string `json:"description"`
	Properties      json.RawMessage `json:"properties"`
}

func parseAzureActivityLogEvent(raw json.RawMessage, sourceID string) (*models.XdrEvent, error) {
	var entry azureActivityLogEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}

	op := entry.OperationName.Value
	classUID := ocsf.ClassCloudAPIActivity
	eventType := "CLOUD_API"

	switch {
	case strings.Contains(op, "signIns") || strings.Contains(op, "signIn"):
		classUID = ocsf.ClassAuthentication
		eventType = "AUTH_LOGIN"
	case strings.Contains(op, "roleAssignments"):
		classUID = ocsf.ClassPolicyChange
		eventType = "POLICY_CHANGE"
	case strings.Contains(op, "write") || strings.Contains(op, "delete"):
		classUID = ocsf.ClassCloudAPIActivity
		eventType = "CLOUD_MUTATION"
	}

	ev := &models.XdrEvent{
		ClassUID:    classUID,
		CategoryUID: ocsf.CategoryCloudActivity,
		SourceType:  "cloud",
		SourceID:    sourceID,
		TenantID:    "default",
		UserUID:     entry.Caller,
		RawLog:      string(raw),
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.ReceivedAt = time.Now()
	ev.Event.EventType = eventType

	if t, err := time.Parse(time.RFC3339Nano, entry.EventTimestamp); err == nil {
		ev.Event.Timestamp = t
	} else {
		ev.Event.Timestamp = time.Now()
	}

	payload := map[string]interface{}{
		"operation":      op,
		"category":       entry.Category.Value,
		"status":         entry.Status.Value,
		"caller":         entry.Caller,
		"resource_id":    entry.ResourceID,
		"subscription":   entry.SubscriptionID,
		"correlation_id": entry.CorrelationID,
		"level":          entry.Level,
	}
	data, _ := json.Marshal(payload)
	ev.Event.Payload = data
	return ev, nil
}
