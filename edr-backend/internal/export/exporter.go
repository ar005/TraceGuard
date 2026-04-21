// internal/export/exporter.go
//
// ExportManager fans out alerts and XDR events to configured export destinations:
//
//   slack        — Slack incoming webhook
//   pagerduty    — PagerDuty Events API v2
//   webhook      — generic HTTP POST (Teams, Discord, custom SIEM)
//   syslog_cef   — CEF over UDP/TCP syslog (Splunk, ELK, QRadar)
//   email        — SMTP email per-alert

package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// DestinationStore is the DB interface required by ExportManager.
type DestinationStore interface {
	ListEnabledExportDestinations(ctx context.Context) ([]models.ExportDestination, error)
}

// ExportManager fans out to all enabled export destinations.
type ExportManager struct {
	store DestinationStore
	log   zerolog.Logger
}

// New creates an ExportManager.
func New(store DestinationStore, log zerolog.Logger) *ExportManager {
	return &ExportManager{
		store: store,
		log:   log.With().Str("component", "export").Logger(),
	}
}

// ExportAlert sends an alert to all matching enabled destinations.
func (m *ExportManager) ExportAlert(ctx context.Context, alert *models.Alert) {
	dests, err := m.store.ListEnabledExportDestinations(ctx)
	if err != nil {
		m.log.Warn().Err(err).Msg("list export destinations failed")
		return
	}
	for _, d := range dests {
		if d.FilterSev > 0 && alert.Severity < d.FilterSev {
			continue
		}
		dest := d
		go func() {
			if err := m.send(context.Background(), dest, alert, nil); err != nil {
				m.log.Warn().Err(err).Str("dest", dest.Name).Str("type", dest.DestType).Msg("export alert failed")
			}
		}()
	}
}

// ExportXdrEvent sends an XDR event to matching destinations.
func (m *ExportManager) ExportXdrEvent(ctx context.Context, ev *models.XdrEvent) {
	dests, err := m.store.ListEnabledExportDestinations(ctx)
	if err != nil {
		return
	}
	for _, d := range dests {
		if len(d.FilterTypes) > 0 && !sliceContains([]string(d.FilterTypes), ev.SourceType) {
			continue
		}
		dest := d
		go func() {
			if err := m.send(context.Background(), dest, nil, ev); err != nil {
				m.log.Warn().Err(err).Str("dest", dest.Name).Msg("export xdr event failed")
			}
		}()
	}
}

func (m *ExportManager) send(ctx context.Context, d models.ExportDestination, alert *models.Alert, ev *models.XdrEvent) error {
	switch d.DestType {
	case "slack":
		return sendSlack(ctx, d.Config, alert, ev)
	case "pagerduty":
		return sendPagerDuty(ctx, d.Config, alert)
	case "webhook":
		return sendWebhook(ctx, d.Config, alert, ev)
	case "syslog_cef":
		return sendSyslogCEF(d.Config, alert, ev)
	case "email":
		return sendEmail(d.Config, alert)
	default:
		return fmt.Errorf("unknown dest_type %q", d.DestType)
	}
}

// ── Slack ─────────────────────────────────────────────────────────────────────

type slackCfg struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
}

func sendSlack(ctx context.Context, cfg json.RawMessage, alert *models.Alert, ev *models.XdrEvent) error {
	var c slackCfg
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	if c.WebhookURL == "" {
		return fmt.Errorf("slack: webhook_url required")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"text":     buildText(alert, ev),
		"username": "TraceGuard",
		"channel":  c.Channel,
	})
	return postJSON(ctx, c.WebhookURL, payload)
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

type pdCfg struct {
	IntegrationKey string `json:"integration_key"`
}

func sendPagerDuty(ctx context.Context, cfg json.RawMessage, alert *models.Alert) error {
	if alert == nil {
		return nil
	}
	var c pdCfg
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"routing_key":  c.IntegrationKey,
		"event_action": "trigger",
		"dedup_key":    alert.ID,
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("[%s] %s on %s", sevLabel(alert.Severity), alert.Title, alert.Hostname),
			"severity":  pdSev(alert.Severity),
			"source":    "TraceGuard",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
	return postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", payload)
}

// ── Generic webhook ───────────────────────────────────────────────────────────

type webhookCfg struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func sendWebhook(ctx context.Context, cfg json.RawMessage, alert *models.Alert, ev *models.XdrEvent) error {
	var c webhookCfg
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	if c.URL == "" {
		return fmt.Errorf("webhook: url required")
	}
	var body interface{}
	if alert != nil {
		body = alert
	} else {
		body = ev
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── CEF syslog ────────────────────────────────────────────────────────────────

type syslogCEFCfg struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`     // default 514
	Protocol string `json:"protocol"` // udp|tcp (default udp)
	Facility int    `json:"facility"` // default 1 (user)
}

func sendSyslogCEF(cfg json.RawMessage, alert *models.Alert, ev *models.XdrEvent) error {
	var c syslogCEFCfg
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	if c.Host == "" {
		return fmt.Errorf("syslog_cef: host required")
	}
	if c.Port == 0 {
		c.Port = 514
	}
	if c.Protocol == "" {
		c.Protocol = "udp"
	}
	if c.Facility == 0 {
		c.Facility = 1
	}

	pri := c.Facility*8 + 6 // informational
	if alert != nil && alert.Severity >= 3 {
		pri = c.Facility*8 + 3 // error
	}
	msg := fmt.Sprintf("<%d>%s TraceGuard: %s\n", pri, time.Now().Format(time.RFC3339), buildCEF(alert, ev))

	conn, err := net.DialTimeout(c.Protocol, fmt.Sprintf("%s:%d", c.Host, c.Port), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}

// buildCEF produces a CEF:0 formatted event string.
func buildCEF(alert *models.Alert, ev *models.XdrEvent) string {
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		return strings.ReplaceAll(s, "|", `\|`)
	}
	if alert != nil {
		ext := fmt.Sprintf("dhost=%s msg=%s ruleName=%s", esc(alert.Hostname), esc(alert.Title), esc(alert.RuleName))
		return fmt.Sprintf("CEF:0|TraceGuard|EDR|1.0|%s|%s|%d|%s",
			esc(alert.RuleID), esc(alert.Title), cefSev(alert.Severity), ext)
	}
	if ev != nil {
		src := ""
		if ev.SrcIP != nil {
			src = "src=" + ev.SrcIP.String()
		}
		ext := fmt.Sprintf("%s suser=%s", src, esc(ev.UserUID))
		return fmt.Sprintf("CEF:0|TraceGuard|EDR|1.0|%s|%s|5|%s",
			ev.Event.EventType, ev.Event.EventType, ext)
	}
	return "CEF:0|TraceGuard|EDR|1.0|unknown|unknown|0|"
}

// ── Email ─────────────────────────────────────────────────────────────────────

type emailCfg struct {
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

func sendEmail(cfg json.RawMessage, alert *models.Alert) error {
	if alert == nil {
		return nil
	}
	var c emailCfg
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	if c.SMTPHost == "" || len(c.To) == 0 {
		return fmt.Errorf("email: smtp_host and to required")
	}
	if c.SMTPPort == 0 {
		c.SMTPPort = 587
	}

	subject := fmt.Sprintf("TraceGuard Alert [%s]: %s", sevLabel(alert.Severity), alert.Title)
	body := buildText(alert, nil)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		c.From, strings.Join(c.To, ", "), subject, body)

	addr := fmt.Sprintf("%s:%d", c.SMTPHost, c.SMTPPort)
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.SMTPHost)
	}
	return smtp.SendMail(addr, auth, c.From, c.To, []byte(msg))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func postJSON(ctx context.Context, url string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

func buildText(alert *models.Alert, ev *models.XdrEvent) string {
	if alert != nil {
		return fmt.Sprintf("[%s] %s\nHost: %s | Rule: %s | Agent: %s",
			sevLabel(alert.Severity), alert.Title, alert.Hostname, alert.RuleName, alert.AgentID)
	}
	if ev != nil {
		return fmt.Sprintf("[XDR] %s | User: %s | Source: %s", ev.Event.EventType, ev.UserUID, ev.SourceType)
	}
	return ""
}

func sevLabel(sev int16) string {
	switch sev {
	case 1:
		return "LOW"
	case 2:
		return "MEDIUM"
	case 3:
		return "HIGH"
	case 4:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

func pdSev(sev int16) string {
	switch sev {
	case 4:
		return "critical"
	case 3:
		return "error"
	case 2:
		return "warning"
	}
	return "info"
}

func cefSev(sev int16) int {
	switch sev {
	case 1:
		return 2
	case 2:
		return 5
	case 3:
		return 8
	case 4:
		return 10
	}
	return 5
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
