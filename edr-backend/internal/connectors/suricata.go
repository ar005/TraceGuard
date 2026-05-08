// internal/connectors/suricata.go
//
// SuricataConnector — file-tail mode for Suricata EVE JSON logs.
// Tails eve.json (or a configured path) and emits XdrEvents.
//
// EVE JSON event_type mapping:
//   alert  → ClassUID 2004 (Detection Finding)
//   dns    → ClassUID 4003 (DNSActivity)
//   http   → ClassUID 4002 (HTTPActivity)
//   tls    → ClassUID 4001 (NetworkActivity)
//   flow   → ClassUID 4001 (NetworkActivity)
//   (other)→ ClassUID 4001 (NetworkActivity)
//
// Config stored in xdr_sources.config (JSON):
//   {"eve_log": "/var/log/suricata/eve.json", "poll_interval_ms": 500}

package connectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/ocsf"
)

func init() {
	RegisterFactory("suricata", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg SuricataConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("suricata config: %w", err)
		}
		if cfg.EVELog == "" {
			cfg.EVELog = "/var/log/suricata/eve.json"
		}
		if cfg.PollIntervalMS <= 0 {
			cfg.PollIntervalMS = 500
		}
		return &SuricataConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "suricata").Str("id", src.ID).Logger(),
		}, nil
	})
}

// SuricataConfig is stored as JSON in xdr_sources.config.
type SuricataConfig struct {
	EVELog         string `json:"eve_log"`
	PollIntervalMS int    `json:"poll_interval_ms"`
}

// SuricataConnector tails Suricata's EVE JSON log and emits XdrEvents.
type SuricataConnector struct {
	id  string
	cfg SuricataConfig
	log zerolog.Logger
}

func (c *SuricataConnector) ID() string         { return c.id }
func (c *SuricataConnector) SourceType() string { return "network" }

func (c *SuricataConnector) Start(ctx context.Context, sink EventSink) error {
	st := &surTailState{}

	interval := time.Duration(c.cfg.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.tailFile(ctx, st, sink); err != nil {
				c.log.Debug().Err(err).Msg("tail error")
			}
		}
	}
}

type surTailState struct{ offset int64 }

func (c *SuricataConnector) tailFile(ctx context.Context, st *surTailState, sink EventSink) error {
	f, err := os.Open(c.cfg.EVELog)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < st.offset {
		st.offset = 0
	}
	if info.Size() == st.offset {
		return nil
	}
	if _, err := f.Seek(st.offset, 0); err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB line buffer for large JSON
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		st.offset += int64(len(line)) + 1

		ev, err := parseSuricataEVE(line, c.id)
		if err != nil {
			continue
		}
		if err := sink.Publish(ev); err != nil {
			c.log.Warn().Err(err).Msg("sink publish failed")
		}
		metrics.XdrEventsReceived.WithLabelValues("network").Inc()
	}
	return scanner.Err()
}

func (c *SuricataConnector) Health(ctx context.Context) error {
	if _, err := os.Stat(c.cfg.EVELog); err != nil {
		return fmt.Errorf("suricata eve log %q: %w", c.cfg.EVELog, err)
	}
	return nil
}

// eveRecord is the minimal set of fields we need from an EVE JSON record.
type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dest_ip"`
	DstPort   int    `json:"dest_port"`
	Proto     string `json:"proto"`

	Alert *struct {
		Action      string `json:"action"`
		SignatureID  int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert,omitempty"`

	DNS *struct {
		Type  string `json:"type"`
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
		RCode  string `json:"rcode"`
	} `json:"dns,omitempty"`

	HTTP *struct {
		Hostname string `json:"hostname"`
		URL      string `json:"url"`
		Method   string `json:"http_method"`
		Status   int    `json:"status"`
		UA       string `json:"http_user_agent"`
	} `json:"http,omitempty"`
}

func parseSuricataEVE(raw []byte, sourceID string) (*models.XdrEvent, error) {
	var rec eveRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}

	classUID := ocsf.ClassNetworkActivity
	eventType := "NET_FLOW"
	switch rec.EventType {
	case "alert":
		classUID = ocsf.ClassDetectionFinding
		eventType = "ALERT"
	case "dns":
		classUID = ocsf.ClassDNSActivity
		eventType = "NET_DNS"
	case "http":
		classUID = ocsf.ClassHTTPActivity
		eventType = "NET_HTTP"
	}

	ev := &models.XdrEvent{
		ClassUID:    classUID,
		CategoryUID: ocsf.CategoryNetworkActivity,
		SourceType:  "network",
		SourceID:    sourceID,
		TenantID:    "default",
		RawLog:      string(raw),
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.ReceivedAt = time.Now()
	ev.Event.EventType = eventType

	if rec.Timestamp != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.999999-0700", rec.Timestamp); err == nil {
			ev.Event.Timestamp = t
		}
	}
	if ev.Event.Timestamp.IsZero() {
		ev.Event.Timestamp = time.Now()
	}

	if rec.SrcIP != "" {
		ip := net.ParseIP(rec.SrcIP)
		ev.SrcIP = &ip
	}
	if rec.DstIP != "" {
		ip := net.ParseIP(rec.DstIP)
		ev.DstIP = &ip
	}

	payload := map[string]interface{}{
		"proto": rec.Proto,
	}
	if rec.SrcPort > 0 {
		payload["src_port"] = rec.SrcPort
	}
	if rec.DstPort > 0 {
		payload["dst_port"] = rec.DstPort
	}
	switch rec.EventType {
	case "alert":
		if rec.Alert != nil {
			payload["action"] = rec.Alert.Action
			payload["signature_id"] = rec.Alert.SignatureID
			payload["signature"] = rec.Alert.Signature
			payload["category"] = rec.Alert.Category
			payload["severity"] = rec.Alert.Severity
		}
	case "dns":
		if rec.DNS != nil {
			payload["type"] = rec.DNS.Type
			payload["domain"] = rec.DNS.RRName
			payload["rrtype"] = rec.DNS.RRType
			payload["rcode"] = rec.DNS.RCode
		}
	case "http":
		if rec.HTTP != nil {
			payload["host"] = rec.HTTP.Hostname
			payload["uri"] = rec.HTTP.URL
			payload["method"] = rec.HTTP.Method
			payload["status_code"] = rec.HTTP.Status
			payload["user_agent"] = rec.HTTP.UA
		}
	}

	data, _ := json.Marshal(payload)
	ev.Event.Payload = data
	return ev, nil
}
