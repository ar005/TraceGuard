// internal/connectors/gcp.go
//
// GCPConnector — pulls audit log entries from a GCP Pub/Sub subscription.
// Uses the Pub/Sub REST API with a service-account JWT (RS256) for auth.
//
// OCSF mapping:
//   google.iam.*                    → ClassUID 6001 (PolicyChange)
//   google.login / google.accounts  → ClassUID 3002 (Authentication)
//   (other)                         → ClassUID 4001 (CloudAPIActivity)
//
// Config stored in xdr_sources.config (JSON):
//   {
//     "project_id":        "my-project",
//     "subscription":      "projects/my-project/subscriptions/audit-log-sub",
//     "service_account_json": "{...}", // full SA key JSON
//     "poll_interval_ms":  30000,
//     "max_messages":      100
//   }

package connectors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/ocsf"
)

func init() {
	RegisterFactory("gcp", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg GCPConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("gcp config: %w", err)
		}
		if cfg.ProjectID == "" || cfg.Subscription == "" {
			return nil, fmt.Errorf("gcp config: project_id and subscription required")
		}
		if cfg.ServiceAccountJSON == "" {
			return nil, fmt.Errorf("gcp config: service_account_json required")
		}
		if cfg.PollIntervalMS <= 0 {
			cfg.PollIntervalMS = 30_000
		}
		if cfg.MaxMessages <= 0 {
			cfg.MaxMessages = 100
		}
		c := &GCPConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "gcp").Str("id", src.ID).Logger(),
		}
		if err := c.loadServiceAccount(); err != nil {
			return nil, fmt.Errorf("gcp service account: %w", err)
		}
		return c, nil
	})
}

// GCPConfig is stored as JSON in xdr_sources.config.
type GCPConfig struct {
	ProjectID          string `json:"project_id"`
	Subscription       string `json:"subscription"` // full resource name
	ServiceAccountJSON string `json:"service_account_json"`
	PollIntervalMS     int    `json:"poll_interval_ms"`
	MaxMessages        int    `json:"max_messages"`
}

type gcpServiceAccount struct {
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`
}

// GCPConnector pulls Pub/Sub messages and emits XdrEvents.
type GCPConnector struct {
	id          string
	cfg         GCPConfig
	log         zerolog.Logger
	sa          gcpServiceAccount
	rsaKey      *rsa.PrivateKey
	accessToken string
	tokenExpiry time.Time
}

func (c *GCPConnector) ID() string         { return c.id }
func (c *GCPConnector) SourceType() string { return "cloud" }

func (c *GCPConnector) loadServiceAccount() error {
	if err := json.Unmarshal([]byte(c.cfg.ServiceAccountJSON), &c.sa); err != nil {
		return fmt.Errorf("parse service_account_json: %w", err)
	}
	block, _ := pem.Decode([]byte(c.sa.PrivateKey))
	if block == nil {
		return fmt.Errorf("no PEM block in private_key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}
	c.rsaKey = rk
	return nil
}

func (c *GCPConnector) Start(ctx context.Context, sink EventSink) error {
	interval := time.Duration(c.cfg.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.poll(ctx, sink); err != nil {
				c.log.Debug().Err(err).Msg("gcp poll error")
			}
		}
	}
}

func (c *GCPConnector) poll(ctx context.Context, sink EventSink) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("gcp token: %w", err)
	}

	// Pub/Sub pull
	pullURL := fmt.Sprintf("https://pubsub.googleapis.com/v1/%s:pull", c.cfg.Subscription)
	body, _ := json.Marshal(map[string]interface{}{
		"maxMessages": c.cfg.MaxMessages,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, pullURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pubsub pull %d: %s", resp.StatusCode, b)
	}

	var pullResp struct {
		ReceivedMessages []struct {
			AckID   string `json:"ackId"`
			Message struct {
				Data        string            `json:"data"` // base64
				Attributes  map[string]string `json:"attributes"`
				MessageID   string            `json:"messageId"`
				PublishTime string            `json:"publishTime"`
			} `json:"message"`
		} `json:"receivedMessages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pullResp); err != nil {
		return err
	}
	if len(pullResp.ReceivedMessages) == 0 {
		return nil
	}

	var ackIDs []string
	for _, msg := range pullResp.ReceivedMessages {
		raw, err := base64.StdEncoding.DecodeString(msg.Message.Data)
		if err != nil {
			continue
		}
		ev, err := parseGCPAuditLogEntry(raw, c.id)
		if err != nil {
			continue
		}
		if err := sink.Publish(ev); err != nil {
			c.log.Warn().Err(err).Msg("sink publish failed")
		}
		metrics.XdrEventsReceived.WithLabelValues("cloud").Inc()
		ackIDs = append(ackIDs, msg.AckID)
	}

	if len(ackIDs) > 0 {
		_ = c.acknowledge(ctx, token, ackIDs)
	}
	return nil
}

func (c *GCPConnector) acknowledge(ctx context.Context, token string, ackIDs []string) error {
	ackURL := fmt.Sprintf("https://pubsub.googleapis.com/v1/%s:acknowledge", c.cfg.Subscription)
	body, _ := json.Marshal(map[string]interface{}{"ackIds": ackIDs})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ackURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// getToken fetches a short-lived OAuth2 access token using a service-account JWT.
func (c *GCPConnector) getToken(ctx context.Context) (string, error) {
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	tokenURI := c.sa.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	jwt, err := c.makeJWT(tokenURI)
	if err != nil {
		return "", err
	}

	form := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form))
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
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("gcp oauth: %s", tokenResp.Error)
	}
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	return c.accessToken, nil
}

func (c *GCPConnector) makeJWT(audience string) (string, error) {
	now := time.Now().Unix()
	header := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": c.sa.PrivateKeyID,
	}))
	claims := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]interface{}{
		"iss":   c.sa.ClientEmail,
		"sub":   c.sa.ClientEmail,
		"aud":   audience,
		"scope": "https://www.googleapis.com/auth/pubsub",
		"iat":   now,
		"exp":   now + 3600,
	}))
	sigInput := header + "." + claims
	h := sha256.New()
	h.Write([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.rsaKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", err
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (c *GCPConnector) Health(ctx context.Context) error {
	if _, err := c.getToken(ctx); err != nil {
		return fmt.Errorf("gcp health: %w", err)
	}
	return nil
}

// ── GCP Cloud Audit Log parser ────────────────────────────────────────────────

type gcpAuditLogEntry struct {
	LogName   string `json:"logName"`
	Timestamp string `json:"timestamp"`
	Resource  struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	ProtoPayload struct {
		ServiceName  string `json:"serviceName"`
		MethodName   string `json:"methodName"`
		ResourceName string `json:"resourceName"`
		AuthInfo     struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP string `json:"callerIp"`
		} `json:"requestMetadata"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	} `json:"protoPayload"`
}

func parseGCPAuditLogEntry(raw []byte, sourceID string) (*models.XdrEvent, error) {
	var entry gcpAuditLogEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}

	method := entry.ProtoPayload.MethodName
	service := entry.ProtoPayload.ServiceName

	classUID := ocsf.ClassCloudAPIActivity
	eventType := "CLOUD_API"

	switch {
	case strings.Contains(service, "iam") || strings.Contains(method, "SetIamPolicy"):
		classUID = ocsf.ClassPolicyChange
		eventType = "POLICY_CHANGE"
	case strings.Contains(service, "login") || strings.Contains(service, "accounts"):
		classUID = ocsf.ClassAuthentication
		eventType = "AUTH_LOGIN"
	case strings.Contains(method, "create") || strings.Contains(method, "Create"):
		eventType = "CLOUD_MUTATION"
	case strings.Contains(method, "delete") || strings.Contains(method, "Delete"):
		eventType = "CLOUD_MUTATION"
	}

	ev := &models.XdrEvent{
		ClassUID:    classUID,
		CategoryUID: ocsf.CategoryCloudActivity,
		SourceType:  "cloud",
		SourceID:    sourceID,
		TenantID:    "default",
		UserUID:     entry.ProtoPayload.AuthInfo.PrincipalEmail,
		RawLog:      string(raw),
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.ReceivedAt = time.Now()
	ev.Event.EventType = eventType

	if t, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
		ev.Event.Timestamp = t
	} else {
		ev.Event.Timestamp = time.Now()
	}

	if ip := entry.ProtoPayload.RequestMetadata.CallerIP; ip != "" {
		parsed := parseIP(ip)
		ev.SrcIP = &parsed
	}

	payload := map[string]interface{}{
		"service":       service,
		"method":        method,
		"resource":      entry.ProtoPayload.ResourceName,
		"resource_type": entry.Resource.Type,
		"caller_ip":     entry.ProtoPayload.RequestMetadata.CallerIP,
		"principal":     entry.ProtoPayload.AuthInfo.PrincipalEmail,
		"status_code":   entry.ProtoPayload.Status.Code,
	}
	data, _ := json.Marshal(payload)
	ev.Event.Payload = data
	return ev, nil
}
