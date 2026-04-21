// internal/playbook/actions.go
//
// Built-in playbook action types:
//
//   slack         — POST to Slack incoming webhook
//   pagerduty     — PagerDuty Events API v2
//   webhook       — generic HTTP POST
//   email         — SMTP email (CRITICAL alerts)
//   isolate_host  — live-response host isolation via lrManager
//   block_ip      — live-response block_ip command
//   update_alert  — set alert status/assignee
//   run_hunt      — execute parameterized hunt query

package playbook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/youredr/edr-backend/internal/liveresponse"
	"github.com/youredr/edr-backend/internal/models"
)

// ActionResult captures the outcome of a single action execution.
type ActionResult struct {
	Type    string    `json:"type"`
	Status  string    `json:"status"` // success|failed|skipped
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
}

// ActionContext carries the runtime context for action execution.
type ActionContext struct {
	Alert    *models.Alert
	XdrEvent *models.XdrEvent
	Store    PlaybookStore
	LR       LiveResponder
}

// LiveResponder is the subset of liveresponse.Manager used by playbook actions.
type LiveResponder interface {
	SendCommand(ctx context.Context, agentID, action string, args []string, timeoutSecs int) (*liveresponse.Result, error)
}

// PlaybookStore is the subset of store.Store used during action execution.
type PlaybookStore interface {
	UpdateAlertStatus(ctx context.Context, id, status, assignee, notes string) error
}

// ── dispatcher ────────────────────────────────────────────────────────────────

// Execute dispatches a single action and returns an ActionResult.
func Execute(ctx context.Context, action models.PlaybookAction, ac ActionContext) ActionResult {
	res := ActionResult{Type: action.Type, At: time.Now()}
	var err error

	switch action.Type {
	case "slack":
		err = execSlack(ctx, action.Config, ac)
	case "pagerduty":
		err = execPagerDuty(ctx, action.Config, ac)
	case "webhook":
		err = execWebhook(ctx, action.Config, ac)
	case "email":
		err = execEmail(action.Config, ac)
	case "isolate_host":
		err = execIsolateHost(ctx, action.Config, ac)
	case "block_ip":
		err = execBlockIP(ctx, action.Config, ac)
	case "update_alert":
		err = execUpdateAlert(ctx, action.Config, ac)
	case "disable_identity":
		err = execDisableIdentity(ctx, action.Config, ac)
	case "enrich":
		err = execEnrich(ctx, action.Config, ac)
	case "ticket":
		err = execTicket(ctx, action.Config, ac)
	default:
		res.Status = "skipped"
		res.Detail = fmt.Sprintf("unknown action type %q", action.Type)
		return res
	}

	if err != nil {
		res.Status = "failed"
		res.Detail = err.Error()
	} else {
		res.Status = "success"
	}
	return res
}

// ── action implementations ────────────────────────────────────────────────────

type slackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
}

func execSlack(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	var c slackConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("slack config: %w", err)
	}
	if c.WebhookURL == "" {
		return fmt.Errorf("slack: webhook_url required")
	}

	text := buildAlertMessage(ac)
	payload, _ := json.Marshal(map[string]interface{}{
		"text":     text,
		"username": orDefault(c.Username, "TraceGuard"),
		"channel":  c.Channel,
	})
	return postJSON(ctx, c.WebhookURL, payload, "")
}

type pagerDutyConfig struct {
	IntegrationKey string `json:"integration_key"`
	Severity       string `json:"severity"` // critical|error|warning|info
}

func execPagerDuty(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	var c pagerDutyConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("pagerduty config: %w", err)
	}
	if c.IntegrationKey == "" {
		return fmt.Errorf("pagerduty: integration_key required")
	}

	sev := orDefault(c.Severity, "error")
	summary := buildAlertMessage(ac)
	dedupKey := ""
	if ac.Alert != nil {
		dedupKey = ac.Alert.ID
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"routing_key":  c.IntegrationKey,
		"event_action": "trigger",
		"dedup_key":    dedupKey,
		"payload": map[string]interface{}{
			"summary":   summary,
			"severity":  sev,
			"source":    "TraceGuard",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
	return postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", payload, "")
}

type webhookConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Secret  string            `json:"secret"` // HMAC-SHA256 signing key (optional)
}

func execWebhook(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	var c webhookConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("webhook config: %w", err)
	}
	if c.URL == "" {
		return fmt.Errorf("webhook: url required")
	}

	var body interface{}
	if ac.Alert != nil {
		body = ac.Alert
	} else {
		body = ac.XdrEvent
	}
	payload, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TraceGuard/1.0")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

type emailConfig struct {
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	TLS      bool     `json:"tls"`
}

func execEmail(cfg json.RawMessage, ac ActionContext) error {
	var c emailConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("email config: %w", err)
	}
	if c.SMTPHost == "" || len(c.To) == 0 {
		return fmt.Errorf("email: smtp_host and to required")
	}
	if c.SMTPPort == 0 {
		c.SMTPPort = 587
	}

	subject := "TraceGuard Alert"
	if ac.Alert != nil {
		subject = fmt.Sprintf("TraceGuard ALERT [%s]: %s", severityLabel(ac.Alert.Severity), ac.Alert.Title)
	}
	body := buildAlertMessage(ac)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		c.From, strings.Join(c.To, ", "), subject, body)

	addr := fmt.Sprintf("%s:%d", c.SMTPHost, c.SMTPPort)
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.SMTPHost)
	}

	if c.TLS {
		tlsCfg := &tls.Config{ServerName: c.SMTPHost}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("email TLS dial: %w", err)
		}
		client, err := smtp.NewClient(conn, c.SMTPHost)
		if err != nil {
			return err
		}
		defer client.Close()
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
		if err := client.Mail(c.From); err != nil {
			return err
		}
		for _, to := range c.To {
			if err := client.Rcpt(to); err != nil {
				return err
			}
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(msg))
		w.Close()
		return err
	}

	return smtp.SendMail(addr, auth, c.From, c.To, []byte(msg))
}

type isolateConfig struct {
	AgentID string `json:"agent_id"` // overrides alert's agent_id if set
}

func execIsolateHost(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	if ac.LR == nil {
		return fmt.Errorf("live responder not available")
	}
	var c isolateConfig
	_ = json.Unmarshal(cfg, &c)

	agentID := c.AgentID
	if agentID == "" && ac.Alert != nil {
		agentID = ac.Alert.AgentID
	}
	if agentID == "" {
		return fmt.Errorf("isolate_host: no agent_id")
	}
	_, err := ac.LR.SendCommand(ctx, agentID, "isolate", nil, 30)
	return err
}

type blockIPConfig struct {
	IP      string `json:"ip"`
	AgentID string `json:"agent_id"`
}

func execBlockIP(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	if ac.LR == nil {
		return fmt.Errorf("live responder not available")
	}
	var c blockIPConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	if c.IP == "" {
		return fmt.Errorf("block_ip: ip required")
	}
	agentID := c.AgentID
	if agentID == "" && ac.Alert != nil {
		agentID = ac.Alert.AgentID
	}
	if agentID == "" {
		return fmt.Errorf("block_ip: no agent_id")
	}
	_, err := ac.LR.SendCommand(ctx, agentID, "block_ip", []string{c.IP}, 30)
	return err
}

type updateAlertConfig struct {
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

func execUpdateAlert(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	if ac.Store == nil || ac.Alert == nil {
		return fmt.Errorf("update_alert: no store or alert context")
	}
	var c updateAlertConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	return ac.Store.UpdateAlertStatus(ctx, ac.Alert.ID, c.Status, c.Assignee, "")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func postJSON(ctx context.Context, url string, payload []byte, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return nil
}

func buildAlertMessage(ac ActionContext) string {
	if ac.Alert != nil {
		a := ac.Alert
		return fmt.Sprintf("[%s] %s\nHost: %s | Rule: %s | Agent: %s",
			severityLabel(a.Severity), a.Title, a.Hostname, a.RuleName, a.AgentID)
	}
	if ac.XdrEvent != nil {
		ev := ac.XdrEvent
		return fmt.Sprintf("[XDR] %s from %s", ev.Event.EventType, ev.UserUID)
	}
	return "TraceGuard alert"
}

func severityLabel(sev int16) string {
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

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ── disable_identity ─────────────────────────────────────────────────────────

type disableIdentityConfig struct {
	// Provider is "okta" or "ad".
	Provider string `json:"provider"`
	// OktaDomainEnv is the env var holding the Okta org domain (e.g. "OKTA_DOMAIN").
	OktaDomainEnv string `json:"okta_domain_env"`
	// OktaTokenEnv is the env var holding the Okta API token.
	OktaTokenEnv string `json:"okta_token_env"`
	// Reason is embedded in the deactivation audit note.
	Reason string `json:"reason"`
}

// execDisableIdentity deactivates a user account via Okta or logs the action when
// credentials are not configured (fallback: log only — no-op in demo environments).
func execDisableIdentity(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	var c disableIdentityConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("disable_identity config: %w", err)
	}
	if ac.Alert == nil || ac.Alert.UserUID == "" {
		return fmt.Errorf("disable_identity: no user_uid on alert")
	}
	uid := ac.Alert.UserUID

	if c.Provider != "okta" {
		// AD or unconfigured — log action only (live implementation requires LDAP)
		return fmt.Errorf("disable_identity: provider %q not yet implemented; would disable %s", c.Provider, uid)
	}

	domain := strings.TrimSpace(os.Getenv("OKTA_DOMAIN"))
	token := strings.TrimSpace(os.Getenv("OKTA_TOKEN"))
	if domain == "" || token == "" {
		return fmt.Errorf("disable_identity: OKTA_DOMAIN / OKTA_TOKEN not configured — would disable %s", uid)
	}

	// Step 1: look up user by login/email.
	userURL := fmt.Sprintf("https://%s/api/v1/users/%s", domain, uid)
	req, _ := http.NewRequestWithContext(ctx, "POST",
		userURL+"/lifecycle/deactivate", nil)
	req.Header.Set("Authorization", "SSWS "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("okta deactivate %s: %w", uid, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("okta deactivate %s: HTTP %d: %s", uid, resp.StatusCode, body)
	}
	return nil
}

// ── enrich ───────────────────────────────────────────────────────────────────

type enrichConfig struct {
	// Providers is a list of enrichment sources: "geoip", "virustotal", "whois"
	Providers []string `json:"providers"`
	// VTKeyEnv is the env var holding the VirusTotal API key.
	VTKeyEnv string `json:"vt_key_env"`
}

// execEnrich calls external enrichment services and appends results to the alert's
// description. Full GeoIP/VT integration requires API keys — gracefully degrades.
func execEnrich(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	var c enrichConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("enrich config: %w", err)
	}
	if ac.Alert == nil {
		return nil
	}

	enriched := map[string]interface{}{}

	for _, p := range c.Providers {
		switch p {
		case "virustotal":
			vtKey := strings.TrimSpace(os.Getenv(c.VTKeyEnv))
			if vtKey == "" {
				enriched["virustotal"] = "skipped — VT_API_KEY not configured"
				continue
			}
			// Look up the first src_ip from alert context if available.
			if ac.XdrEvent != nil && ac.XdrEvent.SrcIP != nil {
				ip := ac.XdrEvent.SrcIP.String()
				vtURL := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
				req, _ := http.NewRequestWithContext(ctx, "GET", vtURL, nil)
				req.Header.Set("x-apikey", vtKey)
				client := &http.Client{Timeout: 10 * time.Second}
				if resp, err := client.Do(req); err == nil {
					defer resp.Body.Close()
					var vtResult map[string]interface{}
					if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&vtResult) == nil {
						enriched["virustotal_ip"] = vtResult
					}
				}
			}
		case "geoip", "whois":
			// Bundled GeoIP requires MaxMind DB file — noted as TODO when DB path configured.
			enriched[p] = "available when MaxMind GeoLite2-City.mmdb is configured"
		}
	}

	// Append enrichment summary to alert description (best-effort).
	if len(enriched) > 0 {
		if sum, err := json.Marshal(enriched); err == nil {
			_ = ac.Store.UpdateAlertStatus(ctx, ac.Alert.ID, "", "", "Enrichment: "+string(sum))
		}
	}
	return nil
}

// ── ticket ───────────────────────────────────────────────────────────────────

type ticketConfig struct {
	// System is "jira" (only Jira Cloud supported in Phase 3).
	System string `json:"system"`
	// JiraURLEnv is the env var holding the Jira Cloud base URL (e.g. "https://myorg.atlassian.net").
	JiraURLEnv string `json:"jira_url_env"`
	// JiraUserEnv is the Atlassian account email env var.
	JiraUserEnv string `json:"jira_user_env"`
	// JiraTokenEnv is the Atlassian API token env var.
	JiraTokenEnv string `json:"jira_token_env"`
	// Project is the Jira project key (e.g. "SOC").
	Project string `json:"project"`
	// IssueType is the Jira issue type (e.g. "Incident", "Bug").
	IssueType string `json:"issue_type"`
}

// execTicket creates a Jira Cloud ticket for the alert.
// Falls back to a log-only message when credentials are not configured.
func execTicket(ctx context.Context, cfg json.RawMessage, ac ActionContext) error {
	var c ticketConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("ticket config: %w", err)
	}
	if ac.Alert == nil {
		return nil
	}

	jiraURL := strings.TrimSpace(os.Getenv(c.JiraURLEnv))
	jiraUser := strings.TrimSpace(os.Getenv(c.JiraUserEnv))
	jiraToken := strings.TrimSpace(os.Getenv(c.JiraTokenEnv))

	if jiraURL == "" || jiraUser == "" || jiraToken == "" {
		return fmt.Errorf("ticket: Jira credentials not configured — would create ticket for alert %s", ac.Alert.ID)
	}

	project := orDefault(c.Project, "SOC")
	issueType := orDefault(c.IssueType, "Incident")

	body := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":   map[string]string{"key": project},
			"summary":   fmt.Sprintf("[%s] %s", severityLabel(ac.Alert.Severity), ac.Alert.Title),
			"issuetype": map[string]string{"name": issueType},
			"description": map[string]interface{}{
				"type":    "doc",
				"version": 1,
				"content": []interface{}{
					map[string]interface{}{
						"type": "paragraph",
						"content": []interface{}{
							map[string]interface{}{
								"type": "text",
								"text": fmt.Sprintf("Host: %s\nRule: %s\nAlert ID: %s\n%s",
									ac.Alert.Hostname, ac.Alert.RuleName, ac.Alert.ID, ac.Alert.Description),
							},
						},
					},
				},
			},
		},
	}

	payload, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST",
		jiraURL+"/rest/api/3/issue", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(jiraUser, jiraToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("jira create issue: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("jira HTTP %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
