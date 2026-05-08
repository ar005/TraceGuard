// internal/exfil/detector.go
// Data Exfiltration Detector — watches XDR events for USB bulk copies,
// large outbound flows, and cloud upload activity.

package exfil

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// Thresholds
const (
	usbBulkBytesThresh  int64 = 50 * 1024 * 1024  // 50 MB via USB
	largeOutboundThresh int64 = 100 * 1024 * 1024  // 100 MB outbound network
	cloudUploadThresh   int64 = 25 * 1024 * 1024   // 25 MB cloud upload
	alertCooldown             = 4 * time.Hour
)

// cloudDomains is the list of known cloud storage hosts.
var cloudDomains = []string{
	"s3.amazonaws.com",
	"blob.core.windows.net",
	"storage.googleapis.com",
	"dropbox.com",
	"drive.google.com",
	"onedrive.live.com",
}

// ExfilStore is the minimal store interface required by the detector.
type ExfilStore interface {
	InsertExfilSignal(ctx context.Context, s *models.ExfilSignal) error
	InsertAlert(ctx context.Context, a *models.Alert) error
}

// Detector watches for data exfiltration signals in the XDR event stream.
type Detector struct {
	store   ExfilStore
	log     zerolog.Logger
	mu      sync.Mutex
	alerted map[string]time.Time // "agentID:signalType:target" -> last alert time
}

// New creates a new exfil Detector.
func New(st ExfilStore, log zerolog.Logger) *Detector {
	return &Detector{
		store:   st,
		log:     log.With().Str("component", "exfil-detector").Logger(),
		alerted: make(map[string]time.Time),
	}
}

// Observe inspects an XDR event for exfiltration signals.
func (d *Detector) Observe(ctx context.Context, ev *models.XdrEvent) {
	et := strings.ToUpper(ev.EventType)

	switch {
	case isUSBCopyEvent(et, ev):
		d.checkUSB(ctx, ev)
	case isLargeOutboundEvent(et):
		d.checkLargeOutbound(ctx, ev)
	case isCloudUploadEvent(et, ev):
		d.checkCloudUpload(ctx, ev)
	}
}

// ── USB bulk copy ─────────────────────────────────────────────────────────────

func isUSBCopyEvent(et string, ev *models.XdrEvent) bool {
	if et == "USB_WRITE" || et == "USB_FILE_COPY" {
		return true
	}
	if et == "FILE_COPY" {
		devType := payloadStr(ev.Payload, "device_type")
		return strings.EqualFold(devType, "usb")
	}
	return false
}

func (d *Detector) checkUSB(ctx context.Context, ev *models.XdrEvent) {
	bytes := parseBytes(ev.Payload, "bytes", "size")
	if bytes <= usbBulkBytesThresh {
		return
	}
	d.fire(ctx, ev, "usb_bulk_copy", bytes, map[string]interface{}{
		"event_type": ev.EventType,
		"bytes":      bytes,
	})
}

// ── Large outbound ────────────────────────────────────────────────────────────

func isLargeOutboundEvent(et string) bool {
	return et == "NETWORK_CONNECTION" || et == "NETWORK_CONNECT" || et == "NETWORK_FLOW"
}

func (d *Detector) checkLargeOutbound(ctx context.Context, ev *models.XdrEvent) {
	bytes := parseBytes(ev.Payload, "bytes_out", "dst_bytes", "bytes_sent")
	if bytes <= largeOutboundThresh {
		return
	}
	// Skip RFC1918 destinations.
	dstIP := payloadStr(ev.Payload, "dst_ip", "destination_ip")
	if dstIP == "" && ev.DstIP != nil {
		dstIP = ev.DstIP.String()
	}
	if isPrivateIP(dstIP) {
		return
	}
	d.fire(ctx, ev, "large_outbound", bytes, map[string]interface{}{
		"event_type": ev.EventType,
		"dst_ip":     dstIP,
		"bytes":      bytes,
	})
}

// ── Cloud upload ──────────────────────────────────────────────────────────────

func isCloudUploadEvent(et string, ev *models.XdrEvent) bool {
	if et != "CLOUD_API" && et != "CLOUD_MUTATION" && et != "HTTP_REQUEST" {
		return false
	}
	method := strings.ToUpper(payloadStr(ev.Payload, "method"))
	if method != "PUT" && method != "POST" {
		return false
	}
	domain := payloadStr(ev.Payload, "domain", "host", "url")
	return matchesCloudDomain(domain)
}

func (d *Detector) checkCloudUpload(ctx context.Context, ev *models.XdrEvent) {
	bytes := parseBytes(ev.Payload, "bytes", "bytes_out", "content_length", "size")
	if bytes > 0 && bytes <= cloudUploadThresh {
		return
	}
	// If URL matches cloud storage but bytes unavailable, fire with bytes=0.
	domain := payloadStr(ev.Payload, "domain", "host", "url")
	d.fire(ctx, ev, "cloud_upload", bytes, map[string]interface{}{
		"event_type": ev.EventType,
		"domain":     domain,
		"bytes":      bytes,
	})
}

// ── Shared fire logic ─────────────────────────────────────────────────────────

func (d *Detector) fire(ctx context.Context, ev *models.XdrEvent, signalType string, bytes int64, detail map[string]interface{}) {
	target := payloadStr(ev.Payload, "dst_ip", "domain", "host", "url", "device")
	dedupKey := fmt.Sprintf("%s:%s:%s", ev.AgentID, signalType, target)

	d.mu.Lock()
	last, hit := d.alerted[dedupKey]
	if hit && time.Since(last) < alertCooldown {
		d.mu.Unlock()
		return
	}
	d.alerted[dedupKey] = time.Now()
	d.mu.Unlock()

	detailJSON, _ := json.Marshal(detail)

	sig := &models.ExfilSignal{
		ID:         "exfil-" + uuid.New().String(),
		TenantID:   ev.TenantID,
		AgentID:    ev.AgentID,
		Hostname:   ev.Hostname,
		SignalType: signalType,
		Detail:     json.RawMessage(detailJSON),
		Bytes:      bytes,
		DetectedAt: time.Now(),
	}

	alertID := "alert-" + uuid.New().String()
	sig.AlertID = alertID

	humanLabel := humanReadable(signalType)
	alert := &models.Alert{
		ID:          alertID,
		TenantID:    ev.TenantID,
		AgentID:     ev.AgentID,
		Hostname:    ev.Hostname,
		Title:       "Data Exfiltration: " + humanLabel,
		Description: fmt.Sprintf("Exfiltration signal '%s' detected on agent %s (%s). Bytes: %d.", signalType, ev.AgentID, ev.Hostname, bytes),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-exfil-" + signalType,
		RuleName:    "Data Exfiltration: " + humanLabel,
		MitreIDs:    []string{"T1048", "T1567"},
		SourceTypes: []string{"endpoint"},
	}

	if err := d.store.InsertExfilSignal(ctx, sig); err != nil {
		d.log.Error().Err(err).Str("signal_type", signalType).Msg("insert exfil signal")
	}
	if err := d.store.InsertAlert(ctx, alert); err != nil {
		d.log.Error().Err(err).Str("signal_type", signalType).Msg("insert exfil alert")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func payloadStr(payload json.RawMessage, keys ...string) string {
	if len(payload) == 0 {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func parseBytes(payload json.RawMessage, keys ...string) int64 {
	if len(payload) == 0 {
		return 0
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return 0
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case float64:
			return int64(val)
		case string:
			n, err := strconv.ParseInt(val, 10, 64)
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func isPrivateIP(ipStr string) bool {
	if ipStr == "" {
		return true // treat unknown as private (safe default)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func matchesCloudDomain(s string) bool {
	lower := strings.ToLower(s)
	for _, d := range cloudDomains {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

func humanReadable(signalType string) string {
	switch signalType {
	case "usb_bulk_copy":
		return "USB Bulk Copy"
	case "large_outbound":
		return "Large Outbound Transfer"
	case "cloud_upload":
		return "Cloud Upload"
	default:
		return signalType
	}
}
