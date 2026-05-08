// internal/connectors/cloudtrail.go
//
// CloudTrailConnector — polls AWS SQS for CloudTrail S3 delivery notifications,
// downloads and parses the JSON log files, and emits XdrEvents.
//
// Architecture:
//   CloudTrail → S3 bucket → SQS notification → this connector → XdrEvent
//
// OCSF mapping:
//   ConsoleLogin              → ClassUID 3002 (Authentication)
//   AssumeRole / GetCallerIdentity → ClassUID 3002 (Authentication)
//   Create*/Delete*/Put*/Attach*/Detach* → ClassUID 6001 (PolicyChange/CloudAPIActivity)
//   (other)                   → ClassUID 4001 (NetworkActivity)
//
// Auth: AWS credentials from environment (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)
// or EC2 instance profile metadata.
//
// Config stored in xdr_sources.config (JSON):
//   {
//     "queue_url":        "https://sqs.us-east-1.amazonaws.com/123/cloudtrail-notif",
//     "region":           "us-east-1",
//     "poll_interval_ms": 5000,
//     "max_messages":     10
//   }

package connectors

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/ocsf"
)

func init() {
	RegisterFactory("cloudtrail", func(src *models.XdrSource, log zerolog.Logger) (Connector, error) {
		var cfg CloudTrailConfig
		if err := json.Unmarshal(src.Config, &cfg); err != nil {
			return nil, fmt.Errorf("cloudtrail config: %w", err)
		}
		if cfg.QueueURL == "" {
			return nil, fmt.Errorf("cloudtrail config: queue_url required")
		}
		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
		if cfg.PollIntervalMS <= 0 {
			cfg.PollIntervalMS = 5_000
		}
		if cfg.MaxMessages <= 0 {
			cfg.MaxMessages = 10
		}
		return &CloudTrailConnector{
			id:  src.ID,
			cfg: cfg,
			log: log.With().Str("connector", "cloudtrail").Str("id", src.ID).Logger(),
		}, nil
	})
}

// CloudTrailConfig is stored as JSON in xdr_sources.config.
type CloudTrailConfig struct {
	QueueURL       string `json:"queue_url"`
	Region         string `json:"region"`
	PollIntervalMS int    `json:"poll_interval_ms"`
	MaxMessages    int    `json:"max_messages"`
	// Optional explicit credentials (prefer env/instance-profile)
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// CloudTrailConnector reads CloudTrail events from SQS-delivered S3 objects.
type CloudTrailConnector struct {
	id  string
	cfg CloudTrailConfig
	log zerolog.Logger
}

func (c *CloudTrailConnector) ID() string         { return c.id }
func (c *CloudTrailConnector) SourceType() string { return "cloud" }

func (c *CloudTrailConnector) Start(ctx context.Context, sink EventSink) error {
	interval := time.Duration(c.cfg.PollIntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.pollSQS(ctx, sink); err != nil {
				c.log.Debug().Err(err).Msg("sqs poll error")
			}
		}
	}
}

func (c *CloudTrailConnector) pollSQS(ctx context.Context, sink EventSink) error {
	creds := c.credentials()

	// Receive messages from SQS
	params := url.Values{
		"Action":              {"ReceiveMessage"},
		"MaxNumberOfMessages": {fmt.Sprint(c.cfg.MaxMessages)},
		"WaitTimeSeconds":     {"1"},
		"Version":             {"2012-11-05"},
	}

	body, err := c.sqsRequest(ctx, creds, "POST", c.cfg.QueueURL, params.Encode())
	if err != nil {
		return err
	}

	// Parse XML minimally — extract Body and ReceiptHandle
	messages := parseReceiveMessageResponse(body)
	for _, msg := range messages {
		if err := c.processMessage(ctx, creds, msg, sink); err != nil {
			c.log.Warn().Err(err).Msg("message processing error")
		}
	}
	return nil
}

func (c *CloudTrailConnector) processMessage(ctx context.Context, creds awsCreds, msg sqsMessage, sink EventSink) error {
	// The SQS message body is an SNS notification wrapping an S3 event.
	var snsEnvelope struct {
		Message string `json:"Message"`
	}
	if err := json.Unmarshal([]byte(msg.Body), &snsEnvelope); err != nil {
		// Maybe it's a direct S3 event (SQS direct delivery)
		snsEnvelope.Message = msg.Body
	}

	var s3Event struct {
		Records []struct {
			S3 struct {
				Bucket struct{ Name string `json:"name"` } `json:"bucket"`
				Object struct{ Key string `json:"key"` }  `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
	}
	if err := json.Unmarshal([]byte(snsEnvelope.Message), &s3Event); err != nil {
		return fmt.Errorf("parse s3 event: %w", err)
	}

	for _, record := range s3Event.Records {
		bucket := record.S3.Bucket.Name
		key := record.S3.Object.Key
		if bucket == "" || key == "" {
			continue
		}
		events, err := c.downloadCloudTrailLog(ctx, creds, bucket, key)
		if err != nil {
			c.log.Warn().Err(err).Str("key", key).Msg("download failed")
			continue
		}
		for _, ev := range events {
			if pubErr := sink.Publish(ev); pubErr != nil {
				c.log.Warn().Err(pubErr).Msg("sink publish failed")
			}
			metrics.XdrEventsReceived.WithLabelValues("cloud").Inc()
		}
	}

	// Delete the processed message
	deleteParams := url.Values{
		"Action":        {"DeleteMessage"},
		"ReceiptHandle": {msg.ReceiptHandle},
		"Version":       {"2012-11-05"},
	}
	_, _ = c.sqsRequest(ctx, creds, "POST", c.cfg.QueueURL, deleteParams.Encode())
	return nil
}

func (c *CloudTrailConnector) downloadCloudTrailLog(ctx context.Context, creds awsCreds, bucket, key string) ([]*models.XdrEvent, error) {
	s3URL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, c.cfg.Region, url.PathEscape(key))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s3URL, nil)
	awsSign(req, creds, c.cfg.Region, "s3", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("s3 get %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(key, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}

	var ctLog struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.NewDecoder(reader).Decode(&ctLog); err != nil {
		return nil, fmt.Errorf("decode cloudtrail log: %w", err)
	}

	events := make([]*models.XdrEvent, 0, len(ctLog.Records))
	for _, raw := range ctLog.Records {
		ev, err := parseCloudTrailRecord(raw, c.id)
		if err == nil {
			events = append(events, ev)
		}
	}
	return events, nil
}

func (c *CloudTrailConnector) Health(ctx context.Context) error {
	creds := c.credentials()
	if creds.AccessKeyID == "" {
		return fmt.Errorf("no AWS credentials available")
	}
	// Quick SQS GetQueueAttributes to check connectivity
	params := url.Values{
		"Action":         {"GetQueueAttributes"},
		"AttributeName.1": {"QueueArn"},
		"Version":        {"2012-11-05"},
	}
	_, err := c.sqsRequest(ctx, creds, "POST", c.cfg.QueueURL, params.Encode())
	return err
}

// ── CloudTrail record parser ──────────────────────────────────────────────────

type ctRecord struct {
	EventTime    time.Time `json:"eventTime"`
	EventSource  string    `json:"eventSource"`
	EventName    string    `json:"eventName"`
	UserIdentity struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		ARN         string `json:"arn"`
		UserName    string `json:"userName"`
		AccountID   string `json:"accountId"`
	} `json:"userIdentity"`
	SourceIPAddress string `json:"sourceIPAddress"`
	RequestParams   json.RawMessage `json:"requestParameters"`
	ResponseElements json.RawMessage `json:"responseElements"`
	ErrorCode   string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	AWS_Region  string `json:"awsRegion"`
}

func parseCloudTrailRecord(raw json.RawMessage, sourceID string) (*models.XdrEvent, error) {
	var rec ctRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}

	classUID := ocsf.ClassCloudAPIActivity
	eventType := "CLOUD_API"
	switch {
	case rec.EventName == "ConsoleLogin":
		classUID = ocsf.ClassAuthentication
		eventType = "AUTH_LOGIN"
	case strings.HasPrefix(rec.EventName, "AssumeRole"),
		strings.HasPrefix(rec.EventName, "GetCallerIdentity"):
		classUID = ocsf.ClassAuthentication
		eventType = "AUTH_ASSUME_ROLE"
	case strings.HasPrefix(rec.EventName, "Create") ||
		strings.HasPrefix(rec.EventName, "Put") ||
		strings.HasPrefix(rec.EventName, "Attach") ||
		strings.HasPrefix(rec.EventName, "Detach") ||
		strings.HasPrefix(rec.EventName, "Delete"):
		classUID = ocsf.ClassCloudAPIActivity
		eventType = "CLOUD_MUTATION"
	}

	userUID := rec.UserIdentity.UserName
	if userUID == "" {
		userUID = rec.UserIdentity.PrincipalID
	}

	ev := &models.XdrEvent{
		ClassUID:    classUID,
		CategoryUID: ocsf.CategoryCloudActivity,
		SourceType:  "cloud",
		SourceID:    sourceID,
		TenantID:    "default",
		UserUID:     userUID,
		RawLog:      string(raw),
	}
	ev.Event.ID = "xdr-" + uuid.New().String()
	ev.Event.Timestamp = rec.EventTime
	if ev.Event.Timestamp.IsZero() {
		ev.Event.Timestamp = time.Now()
	}
	ev.Event.ReceivedAt = time.Now()
	ev.Event.EventType = eventType

	if rec.SourceIPAddress != "" {
		ip := net.ParseIP(rec.SourceIPAddress)
		if ip != nil {
			ev.SrcIP = &ip
		}
	}

	payload := map[string]interface{}{
		"event_name":   rec.EventName,
		"event_source": rec.EventSource,
		"aws_region":   rec.AWS_Region,
		"user_arn":     rec.UserIdentity.ARN,
		"account_id":   rec.UserIdentity.AccountID,
		"error_code":   rec.ErrorCode,
		"error_msg":    rec.ErrorMessage,
	}
	data, _ := json.Marshal(payload)
	ev.Event.Payload = data
	return ev, nil
}

// ── AWS SigV4 helpers ─────────────────────────────────────────────────────────

type awsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func (c *CloudTrailConnector) credentials() awsCreds {
	ak := c.cfg.AccessKeyID
	sk := c.cfg.SecretAccessKey
	if ak == "" {
		ak = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if sk == "" {
		sk = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	return awsCreds{
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
}

func (c *CloudTrailConnector) sqsRequest(ctx context.Context, creds awsCreds, method, queueURL, body string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, queueURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	awsSign(req, creds, c.cfg.Region, "sqs", []byte(body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sqs %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}

// awsSign implements AWS Signature Version 4 for an HTTP request.
func awsSign(req *http.Request, creds awsCreds, region, service string, body []byte) {
	if creds.AccessKeyID == "" {
		return
	}
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzdate)
	if creds.SessionToken != "" {
		req.Header.Set("x-amz-security-token", creds.SessionToken)
	}

	var bodyHash string
	if len(body) > 0 {
		h := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(h[:])
	} else {
		h := sha256.Sum256([]byte{})
		bodyHash = hex.EncodeToString(h[:])
	}
	req.Header.Set("x-amz-content-sha256", bodyHash)

	// Build canonical headers list (sorted)
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if creds.SessionToken != "" {
		headers = append(headers, "x-amz-security-token")
	}
	sort.Strings(headers)
	signedHeaders := strings.Join(headers, ";")

	canonicalHeaders := ""
	for _, h := range headers {
		canonicalHeaders += h + ":" + req.Header.Get(h) + "\n"
	}
	// host header is not yet set — use the URL host
	canonicalHeaders = strings.ReplaceAll(canonicalHeaders, "host:", "host:"+req.URL.Host+"\n")
	canonicalHeaders = strings.TrimSuffix(canonicalHeaders, "\n")
	canonicalHeaders += "\n"

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	credentialScope := datestamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzdate + "\n" + credentialScope + "\n" +
		hex.EncodeToString(hashSHA256([]byte(canonicalRequest)))

	signingKey := deriveSigningKey(creds.SecretAccessKey, datestamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credentialScope, signedHeaders, signature,
	))
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ── SQS XML response parser ───────────────────────────────────────────────────

type sqsMessage struct {
	Body          string
	ReceiptHandle string
}

func parseReceiveMessageResponse(body []byte) []sqsMessage {
	var messages []sqsMessage
	content := string(body)

	// Simple XML extraction — no xml package needed for this structure
	for {
		start := strings.Index(content, "<Message>")
		if start < 0 {
			break
		}
		end := strings.Index(content[start:], "</Message>")
		if end < 0 {
			break
		}
		chunk := content[start : start+end+len("</Message>")]
		content = content[start+end+len("</Message>"):]

		msg := sqsMessage{
			Body:          extractXMLTag(chunk, "Body"),
			ReceiptHandle: extractXMLTag(chunk, "ReceiptHandle"),
		}
		if msg.Body != "" {
			messages = append(messages, msg)
		}
	}
	return messages
}

func extractXMLTag(s, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(s, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(s[start:], close)
	if end < 0 {
		return ""
	}
	// XML unescape common entities
	val := s[start : start+end]
	val = strings.ReplaceAll(val, "&amp;", "&")
	val = strings.ReplaceAll(val, "&lt;", "<")
	val = strings.ReplaceAll(val, "&gt;", ">")
	val = strings.ReplaceAll(val, "&quot;", `"`)
	return val
}
