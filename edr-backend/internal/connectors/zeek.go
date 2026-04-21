// internal/connectors/zeek.go
//
// ZeekConnector — file-tail mode for Zeek Network Security Monitor logs.
// Tails conn.log, dns.log, and http.log from Zeek's current log directory.
//
// Zeek log format: tab-separated values with a #fields header on first read.
// We parse the header once per file open, then parse each subsequent line.
//
// Event mapping:
//   conn.log  → XdrEvent{ClassUID: 4001 (NetworkActivity)}
//   dns.log   → XdrEvent{ClassUID: 4003 (DNSActivity)}
//   http.log  → XdrEvent{ClassUID: 4002 (HTTPActivity)}
//
// Config stored in xdr_sources.config (JSON):
//   {"log_dir": "/opt/zeek/logs/current", "poll_interval_ms": 500}

package connectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/ocsf"
)

func init() {
	RegisterFactory("zeek", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg ZeekConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("zeek config: %w", err)
		}
		if cfg.LogDir == "" {
			cfg.LogDir = "/opt/zeek/logs/current"
		}
		if cfg.PollIntervalMS <= 0 {
			cfg.PollIntervalMS = 500
		}
		return &ZeekConnector{id: src.ID, cfg: cfg, log: log.With().Str("connector", "zeek").Str("id", src.ID).Logger()}, nil
	})
}

// ZeekConfig is stored as JSON in xdr_sources.config.
type ZeekConfig struct {
	LogDir         string `json:"log_dir"`
	PollIntervalMS int    `json:"poll_interval_ms"`
}

// ZeekConnector tails Zeek TSV log files and emits XdrEvents.
type ZeekConnector struct {
	id  string
	cfg ZeekConfig
	log zerolog.Logger
}

type zeekFileState struct {
	offset int64
	fields []string
}

func (c *ZeekConnector) ID() string         { return c.id }
func (c *ZeekConnector) SourceType() string { return "network" }

func (c *ZeekConnector) Start(ctx context.Context, sink EventSink) error {
	logFiles := map[string]int{
		"conn.log": ocsf.ClassNetworkActivity,
		"dns.log":  ocsf.ClassDNSActivity,
		"http.log": ocsf.ClassHTTPActivity,
	}

	states := make(map[string]*zeekFileState, len(logFiles))
	for name := range logFiles {
		states[name] = &zeekFileState{}
	}

	interval := time.Duration(c.cfg.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for name, classUID := range logFiles {
				path := filepath.Join(c.cfg.LogDir, name)
				st := states[name]
				if err := c.tailZeekFile(ctx, path, classUID, st, sink); err != nil {
					c.log.Debug().Err(err).Str("file", name).Msg("tail error")
				}
			}
		}
	}
}

func (c *ZeekConnector) tailZeekFile(ctx context.Context, path string, classUID int, st *zeekFileState, sink EventSink) error {
	f, err := os.Open(path)
	if err != nil {
		return nil // file not yet created — not an error
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	// File rotated (shrank) — reset
	if info.Size() < st.offset {
		st.offset = 0
		st.fields = nil
	}
	if info.Size() == st.offset {
		return nil // no new data
	}

	if _, err := f.Seek(st.offset, 0); err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		st.offset += int64(len(line)) + 1 // +1 for newline

		if strings.HasPrefix(line, "#fields") {
			st.fields = strings.Split(strings.TrimPrefix(line, "#fields\t"), "\t")
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue // skip #separator, #types, etc.
		}
		if st.fields == nil || line == "" {
			continue
		}

		ev, err := parseZeekLine(line, st.fields, classUID, c.id)
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

func (c *ZeekConnector) Health(ctx context.Context) error {
	if _, err := os.Stat(c.cfg.LogDir); err != nil {
		return fmt.Errorf("zeek log dir %q: %w", c.cfg.LogDir, err)
	}
	return nil
}

// parseZeekLine converts one Zeek TSV row to an XdrEvent.
func parseZeekLine(line string, fields []string, classUID int, sourceID string) (*models.XdrEvent, error) {
	vals := strings.Split(line, "\t")
	if len(vals) < len(fields) {
		return nil, fmt.Errorf("short row: %d < %d fields", len(vals), len(fields))
	}

	row := make(map[string]string, len(fields))
	for i, f := range fields {
		if i < len(vals) {
			row[f] = vals[i]
		}
	}

	ev := &models.XdrEvent{
		ClassUID:    classUID,
		CategoryUID: ocsf.CategoryNetworkActivity,
		SourceType:  "network",
		SourceID:    sourceID,
		TenantID:    "default",
		RawLog:      line,
	}

	// Parse timestamp
	if ts, ok := row["ts"]; ok && ts != "-" {
		if f, err := strconv.ParseFloat(ts, 64); err == nil {
			ev.Event.Timestamp = time.Unix(int64(f), int64((f-float64(int64(f)))*1e9))
		}
	}
	if ev.Event.Timestamp.IsZero() {
		ev.Event.Timestamp = time.Now()
	}
	ev.Event.ReceivedAt = time.Now()
	ev.Event.ID = "xdr-" + uuid.New().String()

	// src/dst IPs
	if v := row["id.orig_h"]; v != "" && v != "-" {
		ip := net.ParseIP(v)
		ev.SrcIP = &ip
	}
	if v := row["id.resp_h"]; v != "" && v != "-" {
		ip := net.ParseIP(v)
		ev.DstIP = &ip
	}
	if v := row["id.resp_p"]; v != "" && v != "-" {
		// store in payload
	}

	// Build event-type and payload based on class
	payload := map[string]interface{}{}
	switch classUID {
	case ocsf.ClassNetworkActivity:
		ev.Event.EventType = "NET_FLOW"
		copyFields(payload, row, "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "id.orig_p", "id.resp_p")
	case ocsf.ClassDNSActivity:
		ev.Event.EventType = "NET_DNS"
		ev.CategoryUID = ocsf.CategoryNetworkActivity
		copyFields(payload, row, "query", "qtype_name", "rcode_name", "answers")
		if q := row["query"]; q != "" {
			payload["domain"] = q
		}
	case ocsf.ClassHTTPActivity:
		ev.Event.EventType = "NET_HTTP"
		ev.CategoryUID = ocsf.CategoryNetworkActivity
		copyFields(payload, row, "method", "host", "uri", "status_code", "user_agent", "resp_mime_types")
	}

	data, _ := json.Marshal(payload)
	ev.Event.Payload = data

	return ev, nil
}

func copyFields(dst map[string]interface{}, src map[string]string, keys ...string) {
	for _, k := range keys {
		if v, ok := src[k]; ok && v != "-" && v != "" {
			dst[k] = v
		}
	}
}
