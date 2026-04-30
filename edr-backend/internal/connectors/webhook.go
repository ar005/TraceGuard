// internal/connectors/webhook.go
//
// WebhookConnector — HTTP POST receiver for generic JSON payloads.
// Listens on a configurable HTTP address and path prefix.
// Each POST to /<path_prefix>/<source_id> ingests one JSON event.
//
// The JSON body is accepted verbatim as RawLog; if it contains well-known
// keys (src_ip, dst_ip, timestamp, event_type) they are mapped to XdrEvent.
//
// Config stored in xdr_sources.config (JSON):
//   {"listen_addr": ":9000", "path_prefix": "/webhook", "secret": "optional-hmac-sha256-secret"}
//
// The optional secret enables HMAC-SHA256 validation via the
// X-Webhook-Signature header (hex-encoded SHA256 of the raw body).

package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	RegisterFactory("webhook", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg WebhookConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("webhook config: %w", err)
		}
		if cfg.ListenAddr == "" {
			cfg.ListenAddr = ":9000"
		}
		if cfg.PathPrefix == "" {
			cfg.PathPrefix = "/webhook"
		}
		return &WebhookConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "webhook").Str("id", src.ID).Logger(),
		}, nil
	})
}

// WebhookConfig is stored as JSON in xdr_sources.config.
type WebhookConfig struct {
	ListenAddr string `json:"listen_addr"`
	PathPrefix string `json:"path_prefix"`
	Secret     string `json:"secret"`
}

// WebhookConnector accepts HTTP POST events and emits XdrEvents.
type WebhookConnector struct {
	id  string
	cfg WebhookConfig
	log zerolog.Logger
}

func (c *WebhookConnector) ID() string         { return c.id }
func (c *WebhookConnector) SourceType() string { return "network" }

func (c *WebhookConnector) Start(ctx context.Context, sink EventSink) error {
	mux := http.NewServeMux()
	prefix := strings.TrimSuffix(c.cfg.PathPrefix, "/") + "/"
	mux.HandleFunc(prefix, c.makeHandler(sink))

	srv := &http.Server{
		Addr:         c.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *WebhookConnector) Health(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", c.cfg.ListenAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("webhook listener not reachable at %s: %w", c.cfg.ListenAddr, err)
	}
	conn.Close()
	return nil
}

func (c *WebhookConnector) makeHandler(sink EventSink) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB cap
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		if c.cfg.Secret != "" {
			sig := r.Header.Get("X-Webhook-Signature")
			if !verifyHMAC(body, c.cfg.Secret, sig) {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		}

		ev := parseWebhookBody(body, c.id)
		if err := sink.Publish(ev); err != nil {
			c.log.Warn().Err(err).Msg("sink publish failed")
			http.Error(w, "publish failed", http.StatusInternalServerError)
			return
		}
		metrics.XdrEventsReceived.WithLabelValues("network").Inc()
		w.WriteHeader(http.StatusAccepted)
	}
}

// verifyHMAC computes HMAC-SHA256(secret, body) and compares to sigHex.
func verifyHMAC(body []byte, secret, sigHex string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sigHex))
}

// webhookPayload extracts well-known fields from the inbound JSON.
type webhookPayload struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
}

// ParseWebhookEvent is the exported entry point used by the REST API handler.
func ParseWebhookEvent(body []byte, sourceID string) *models.XdrEvent {
	return parseWebhookBody(body, sourceID)
}

func parseWebhookBody(body []byte, sourceID string) *models.XdrEvent {
	ev := &models.XdrEvent{
		ClassUID:    ocsf.ClassNetworkActivity,
		CategoryUID: ocsf.CategoryNetworkActivity,
		SourceType:  "network",
		SourceID:    sourceID,
		TenantID:    "default",
		RawLog:      string(body),
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.ReceivedAt = time.Now()
	ev.Event.Timestamp = time.Now()
	ev.Event.EventType = "NET_WEBHOOK"
	ev.Event.Payload = body

	var p webhookPayload
	if json.Unmarshal(body, &p) == nil {
		if p.EventType != "" {
			ev.Event.EventType = p.EventType
			ev.ClassUID = ocsf.ClassUID(p.EventType)
			ev.CategoryUID = int16(ocsf.CategoryUID(p.EventType))
		}
		if p.Timestamp != "" {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
				if t, err := time.Parse(layout, p.Timestamp); err == nil {
					ev.Event.Timestamp = t
					break
				}
			}
		}
		if p.SrcIP != "" {
			ip := net.ParseIP(p.SrcIP)
			ev.SrcIP = &ip
		}
		if p.DstIP != "" {
			ip := net.ParseIP(p.DstIP)
			ev.DstIP = &ip
		}
	}
	return ev
}
