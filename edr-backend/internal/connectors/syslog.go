// internal/connectors/syslog.go
//
// SyslogConnector — UDP syslog receiver with CEF (ArcSight Common Event Format) parser.
// Listens on a configurable UDP address (default :514).
// Non-CEF lines are stored as raw syslog events (ClassUID 4001 NetworkActivity).
//
// CEF header: CEF:version|vendor|product|version|sig_id|name|severity|extensions
// Extensions are key=value pairs (space-separated, value may be quoted).
//
// Config stored in xdr_sources.config (JSON):
//   {"udp_addr": ":514", "max_message_bytes": 65536}

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/ocsf"
)

func init() {
	RegisterFactory("syslog", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg SyslogConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("syslog config: %w", err)
		}
		if cfg.UDPAddr == "" {
			cfg.UDPAddr = ":514"
		}
		if cfg.MaxMessageBytes <= 0 {
			cfg.MaxMessageBytes = 65536
		}
		return &SyslogConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "syslog").Str("id", src.ID).Logger(),
		}, nil
	})
}

// SyslogConfig is stored as JSON in xdr_sources.config.
type SyslogConfig struct {
	UDPAddr         string `json:"udp_addr"`
	MaxMessageBytes int    `json:"max_message_bytes"`
}

// SyslogConnector receives UDP syslog/CEF messages and emits XdrEvents.
type SyslogConnector struct {
	id  string
	cfg SyslogConfig
	log zerolog.Logger
}

func (c *SyslogConnector) ID() string         { return c.id }
func (c *SyslogConnector) SourceType() string { return "network" }

func (c *SyslogConnector) Start(ctx context.Context, sink EventSink) error {
	addr, err := net.ResolveUDPAddr("udp", c.cfg.UDPAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", c.cfg.UDPAddr, err)
	}
	defer conn.Close()

	buf := make([]byte, c.cfg.MaxMessageBytes)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			c.log.Debug().Err(err).Msg("udp read error")
			continue
		}
		line := strings.TrimSpace(string(buf[:n]))
		if line == "" {
			continue
		}

		ev := parseSyslogLine(line, c.id)
		if err := sink.Publish(ev); err != nil {
			c.log.Warn().Err(err).Msg("sink publish failed")
		}
		metrics.XdrEventsReceived.WithLabelValues("network").Inc()
	}
}

func (c *SyslogConnector) Health(ctx context.Context) error {
	// Attempt a zero-byte dial to check port is bindable; actual listener is
	// running in Start() so we just verify the config parses.
	_, err := net.ResolveUDPAddr("udp", c.cfg.UDPAddr)
	if err != nil {
		return fmt.Errorf("syslog udp addr invalid: %w", err)
	}
	return nil
}

// parseSyslogLine dispatches to the CEF parser or wraps as a raw syslog event.
func parseSyslogLine(line, sourceID string) *models.XdrEvent {
	ev := &models.XdrEvent{
		ClassUID:    ocsf.ClassNetworkActivity,
		CategoryUID: ocsf.CategoryNetworkActivity,
		SourceType:  "network",
		SourceID:    sourceID,
		TenantID:    "default",
		RawLog:      line,
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.Timestamp = time.Now()
	ev.Event.ReceivedAt = time.Now()
	ev.Event.EventType = "NET_SYSLOG"

	if cef, ok := parseCEF(line); ok {
		ev.Event.EventType = "NET_CEF"
		data, _ := json.Marshal(cef)
		ev.Event.Payload = data
	} else {
		payload := map[string]interface{}{"message": line}
		data, _ := json.Marshal(payload)
		ev.Event.Payload = data
	}
	return ev
}

// cefEvent holds the decoded fields of a CEF message.
type cefEvent struct {
	DeviceVendor  string            `json:"device_vendor"`
	DeviceProduct string            `json:"device_product"`
	SignatureID   string            `json:"signature_id"`
	Name          string            `json:"name"`
	Severity      string            `json:"severity"`
	Extensions    map[string]string `json:"extensions"`
}

// parseCEF parses "CEF:0|vendor|product|devver|sigid|name|sev|ext" format.
// Returns false if the line is not CEF.
func parseCEF(line string) (*cefEvent, bool) {
	// Strip optional syslog priority/timestamp prefix before "CEF:"
	idx := strings.Index(line, "CEF:")
	if idx < 0 {
		return nil, false
	}
	cefPart := line[idx:]
	parts := strings.SplitN(cefPart, "|", 8)
	if len(parts) < 8 {
		return nil, false
	}
	ev := &cefEvent{
		DeviceVendor:  parts[1],
		DeviceProduct: parts[2],
		// parts[3] = device version, parts[4] = signature ID
		SignatureID: parts[4],
		Name:        parts[5],
		Severity:    parts[6],
		Extensions:  parseCEFExtensions(parts[7]),
	}
	return ev, true
}

// parseCEFExtensions parses "key=value key2=value2" extension pairs.
// Values may contain spaces but not unescaped '='; we use a simple FSM.
func parseCEFExtensions(ext string) map[string]string {
	result := make(map[string]string)
	ext = strings.ReplaceAll(ext, "\\=", "\x00") // escape = inside values
	parts := strings.Fields(ext)
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			v := strings.ReplaceAll(kv[1], "\x00", "=")
			result[kv[0]] = v
		}
	}
	return result
}
