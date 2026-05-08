// internal/connectors/okta.go
//
// OktaConnector — polls the Okta System Log API for authentication events.
// Uses cursor-based pagination via the `after` link header.
//
// OCSF mapping:
//   user.session.start      → ClassUID 3002 (Authentication), SUCCESS
//   user.session.end        → ClassUID 3002 (Authentication), LOGOFF
//   user.authentication.*   → ClassUID 3002 (Authentication)
//   policy.*                → ClassUID 6001 (PolicyChange)
//   (other)                 → ClassUID 4001 (NetworkActivity)
//
// Config stored in xdr_sources.config (JSON):
//   {
//     "domain":           "yourorg.okta.com",
//     "api_token":        "SSWS xxxxx",
//     "poll_interval_ms": 30000,
//     "filter":           "eventType sw \"user.authentication\""
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
	RegisterFactory("okta", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg OktaConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("okta config: %w", err)
		}
		if cfg.Domain == "" {
			return nil, fmt.Errorf("okta config: domain is required")
		}
		if cfg.APIToken == "" {
			return nil, fmt.Errorf("okta config: api_token is required")
		}
		if cfg.PollIntervalMS <= 0 {
			cfg.PollIntervalMS = 30_000
		}
		return &OktaConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "okta").Str("id", src.ID).Logger(),
		}, nil
	})
}

// OktaConfig is stored as JSON in xdr_sources.config.
type OktaConfig struct {
	Domain         string `json:"domain"`
	APIToken       string `json:"api_token"`
	PollIntervalMS int    `json:"poll_interval_ms"`
	Filter         string `json:"filter"` // Okta filter expression, e.g. "eventType sw \"user.\""
}

// OktaConnector polls Okta's System Log and emits XdrEvents.
type OktaConnector struct {
	id      string
	cfg     OktaConfig
	log     zerolog.Logger
	cursor  string    // next page URL or `after` cursor
	since   time.Time // last-seen event time for initial hydration
}

func (c *OktaConnector) ID() string         { return c.id }
func (c *OktaConnector) SourceType() string { return "identity" }

func (c *OktaConnector) Start(ctx context.Context, sink EventSink) error {
	c.since = time.Now().Add(-5 * time.Minute) // seed: last 5 min on startup

	interval := time.Duration(c.cfg.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.poll(ctx, sink); err != nil {
				c.log.Debug().Err(err).Msg("okta poll error")
			}
		}
	}
}

func (c *OktaConnector) poll(ctx context.Context, sink EventSink) error {
	var fetchURL string
	if c.cursor != "" {
		fetchURL = c.cursor
	} else {
		fetchURL = c.buildInitialURL()
	}

	for fetchURL != "" {
		events, nextURL, err := c.fetchPage(ctx, fetchURL)
		if err != nil {
			return err
		}
		for _, raw := range events {
			ev, err := parseOktaLogEvent(raw, c.id)
			if err != nil {
				continue
			}
			if err := sink.Publish(ev); err != nil {
				c.log.Warn().Err(err).Msg("sink publish failed")
			}
			metrics.XdrEventsReceived.WithLabelValues("identity").Inc()
		}
		c.cursor = nextURL
		fetchURL = nextURL
	}
	return nil
}

func (c *OktaConnector) buildInitialURL() string {
	base := fmt.Sprintf("https://%s/api/v1/logs", c.cfg.Domain)
	params := url.Values{}
	params.Set("since", c.since.UTC().Format(time.RFC3339))
	params.Set("limit", "100")
	if c.cfg.Filter != "" {
		params.Set("filter", c.cfg.Filter)
	}
	return base + "?" + params.Encode()
}

func (c *OktaConnector) fetchPage(ctx context.Context, pageURL string) ([]json.RawMessage, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "SSWS "+c.cfg.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("okta api %d: %s", resp.StatusCode, body)
	}

	var events []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, "", fmt.Errorf("decode okta response: %w", err)
	}

	// Next page from Link header: <url>; rel="next"
	next := ""
	for _, link := range resp.Header.Values("Link") {
		if strings.Contains(link, `rel="next"`) {
			if start := strings.Index(link, "<"); start >= 0 {
				if end := strings.Index(link[start:], ">"); end >= 0 {
					next = link[start+1 : start+end]
				}
			}
		}
	}
	return events, next, nil
}

func (c *OktaConnector) Health(ctx context.Context) error {
	testURL := fmt.Sprintf("https://%s/api/v1/users/me", c.cfg.Domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	req.Header.Set("Authorization", "SSWS "+c.cfg.APIToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("okta health: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("okta health: invalid api_token")
	}
	return nil
}

// oktaLogEntry holds the minimal fields we need from an Okta System Log event.
type oktaLogEntry struct {
	UUID        string    `json:"uuid"`
	Published   time.Time `json:"published"`
	EventType   string    `json:"eventType"`
	DisplayMsg  string    `json:"displayMessage"`
	Severity    string    `json:"severity"`
	Actor       struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		AlternateID string `json:"alternateId"` // email
	} `json:"actor"`
	Client struct {
		IPAddress string `json:"ipAddress"`
		UserAgent struct{ RawUserAgent string `json:"rawUserAgent"` } `json:"userAgent"`
	} `json:"client"`
	Outcome struct {
		Result string `json:"result"` // SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, CHALLENGE, UNKNOWN
		Reason string `json:"reason"`
	} `json:"outcome"`
}

func parseOktaLogEvent(raw json.RawMessage, sourceID string) (*models.XdrEvent, error) {
	var entry oktaLogEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}

	classUID := ocsf.ClassAuthentication
	eventType := "AUTH_LOGIN"
	switch {
	case strings.HasPrefix(entry.EventType, "user.session.start"):
		eventType = "AUTH_LOGIN"
	case strings.HasPrefix(entry.EventType, "user.session.end"):
		eventType = "AUTH_LOGOFF"
	case strings.HasPrefix(entry.EventType, "user.authentication"):
		eventType = "AUTH_LOGIN"
	case strings.HasPrefix(entry.EventType, "policy."):
		classUID = ocsf.ClassPolicyChange
		eventType = "POLICY_CHANGE"
	default:
		classUID = ocsf.ClassNetworkActivity
		eventType = "IDENTITY_EVENT"
	}

	ev := &models.XdrEvent{
		ClassUID:    classUID,
		CategoryUID: ocsf.CategoryIdentityActivity,
		SourceType:  "identity",
		SourceID:    sourceID,
		TenantID:    "default",
		UserUID:     entry.Actor.AlternateID,
		RawLog:      string(raw),
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.Timestamp = entry.Published
	if ev.Event.Timestamp.IsZero() {
		ev.Event.Timestamp = time.Now()
	}
	ev.Event.ReceivedAt = time.Now()
	ev.Event.EventType = eventType
	ev.Event.AgentID = entry.Actor.ID

	if entry.Client.IPAddress != "" {
		ip := parseIP(entry.Client.IPAddress)
		ev.SrcIP = &ip
	}

	payload := map[string]interface{}{
		"event_type":   entry.EventType,
		"display_msg":  entry.DisplayMsg,
		"severity":     entry.Severity,
		"outcome":      entry.Outcome.Result,
		"reason":       entry.Outcome.Reason,
		"actor_id":     entry.Actor.ID,
		"actor_name":   entry.Actor.DisplayName,
		"actor_email":  entry.Actor.AlternateID,
		"client_ip":    entry.Client.IPAddress,
		"user_agent":   entry.Client.UserAgent.RawUserAgent,
	}
	data, _ := json.Marshal(payload)
	ev.Event.Payload = data
	return ev, nil
}
