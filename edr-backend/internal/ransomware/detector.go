// internal/ransomware/detector.go
//
// RansomwareDetector identifies ransomware behaviour:
//   - >50 file create/write/rename events within 60 seconds on the same agent
//   - Extension matches known ransomware patterns

package ransomware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	fileOpThresh  = 50
	fileOpWindow  = 60 * time.Second
)

// Known ransomware / crypto-locker extensions (lowercase).
var ransomExts = map[string]bool{
	".encrypted": true, ".enc": true, ".locked": true, ".crypto": true,
	".crypted": true, ".crypt": true, ".crypz": true, ".locky": true,
	".zepto": true, ".odin": true, ".thor": true, ".aaa": true,
	".zzzzz": true, ".micro": true, ".cerber": true, ".cerber2": true,
	".cerber3": true, ".wnry": true, ".wcry": true, ".wncry": true,
	".wncryt": true, ".rdm": true, ".r5a": true, ".vvv": true,
	".exx": true, ".xyz": true, ".zzz": true, ".abc": true,
	".rhino": true, ".fun": true, ".pay2me": true, ".pays": true,
	".darkness": true, ".777": true, ".breaking_bad": true,
}

type RansomwareStore interface {
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Detector struct {
	store   RansomwareStore
	log     zerolog.Logger
	mu      sync.Mutex
	fileOps map[string][]time.Time // agentID -> op timestamps
	alerted map[string]bool
}

func New(st *store.Store, log zerolog.Logger) *Detector {
	return &Detector{
		store:   st,
		log:     log.With().Str("component", "ransomware-detector").Logger(),
		fileOps: make(map[string][]time.Time),
		alerted: make(map[string]bool),
	}
}

func (d *Detector) Observe(ctx context.Context, ev *models.XdrEvent) {
	switch ev.Event.EventType {
	case "FILE_CREATE", "FILE_WRITE", "FILE_RENAME", "FILE_MODIFY":
	default:
		return
	}

	var payload map[string]interface{}
	if len(ev.Event.Payload) > 0 {
		_ = json.Unmarshal(ev.Event.Payload, &payload)
	}

	// Check for ransomware extension on the target file
	path, _ := payload["path"].(string)
	if path == "" {
		path, _ = payload["new_path"].(string)
	}
	hasRansomExt := false
	if path != "" {
		ext := strings.ToLower(fileExt(path))
		if ransomExts[ext] {
			hasRansomExt = true
		}
	}

	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.alerted[ev.AgentID] {
		return
	}

	cutoff := ts.Add(-fileOpWindow)
	ops := d.fileOps[ev.AgentID]
	fresh := ops[:0]
	for _, t := range ops {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, ts)
	d.fileOps[ev.AgentID] = fresh

	if len(fresh) >= fileOpThresh || hasRansomExt {
		d.alerted[ev.AgentID] = true
		go d.fireAlert(context.Background(), ev, len(fresh), hasRansomExt, path)
	}
}

func (d *Detector) fireAlert(ctx context.Context, ev *models.XdrEvent, opCount int, hasExt bool, path string) {
	reason := fmt.Sprintf("%d file operations in 60s", opCount)
	if hasExt {
		reason = fmt.Sprintf("ransomware file extension detected: %s", path)
	}
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("Ransomware Behaviour Detected: %s", ev.AgentID),
		Description: fmt.Sprintf(
			"Possible ransomware activity on %s (%s) — %s. Immediate containment recommended.",
			ev.Event.Hostname, ev.AgentID, reason),
		Severity:    5,
		Status:      "OPEN",
		RuleID:      "rule-ransomware",
		RuleName:    "Ransomware Behaviour",
		MitreIDs:    []string{"T1486", "T1490"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		SourceTypes: []string{"endpoint"},
	}
	if err := d.store.InsertAlert(ctx, alert); err != nil {
		d.log.Warn().Err(err).Str("agent_id", ev.AgentID).Msg("ransomware alert insert failed")
	} else {
		d.log.Error().Str("agent_id", ev.AgentID).Str("reason", reason).Msg("RANSOMWARE ALERT FIRED")
	}
}

func fileExt(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	return ""
}
