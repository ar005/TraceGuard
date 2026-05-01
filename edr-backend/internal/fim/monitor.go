// internal/fim/monitor.go
//
// FIMMonitor (File Integrity Monitor) fires alerts when critical system
// files are created, modified, or deleted. No rate limiting — every event
// on a watched path generates an alert.

package fim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// criticalPaths that trigger immediate alerts on any write/delete.
var criticalPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/crontab",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/ssh/sshd_config",
	"/root/.ssh/authorized_keys",
	"/home/",        // catch /.ssh/authorized_keys under any home dir
	"/etc/ld.so.preload",
	"/etc/hosts",
	"/etc/resolv.conf",
	"/boot/",
	"/lib/systemd/",
	"/etc/systemd/",
	"/etc/init.d/",
	"/usr/lib/systemd/",
}

type FIMStore interface {
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Monitor struct {
	store FIMStore
	log   zerolog.Logger
}

func New(st *store.Store, log zerolog.Logger) *Monitor {
	return &Monitor{
		store: st,
		log:   log.With().Str("component", "fim-monitor").Logger(),
	}
}

func (m *Monitor) Observe(ctx context.Context, ev *models.XdrEvent) {
	switch ev.Event.EventType {
	case "FILE_WRITE", "FILE_CREATE", "FILE_DELETE", "FILE_RENAME", "FILE_MODIFY":
	default:
		return
	}

	var payload map[string]interface{}
	if len(ev.Event.Payload) > 0 {
		_ = json.Unmarshal(ev.Event.Payload, &payload)
	}

	path, _ := payload["path"].(string)
	if path == "" {
		path, _ = payload["file_path"].(string)
	}
	if path == "" {
		return
	}

	if !isCriticalPath(path) {
		return
	}

	go m.fireAlert(ctx, ev, path, ev.Event.EventType)
}

func (m *Monitor) fireAlert(ctx context.Context, ev *models.XdrEvent, path, opType string) {
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("FIM Alert: %s on %s", opType, path),
		Description: fmt.Sprintf(
			"Critical file %s was %s on host %s (agent %s). This may indicate privilege escalation, persistence, or compromise.",
			path, strings.ToLower(opType), ev.Event.Hostname, ev.AgentID),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-fim",
		RuleName:    "File Integrity Monitor",
		MitreIDs:    fimMitreIDs(path, opType),
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		SourceTypes: []string{"endpoint"},
	}
	if err := m.store.InsertAlert(ctx, alert); err != nil {
		m.log.Warn().Err(err).Str("path", path).Msg("FIM alert insert failed")
	} else {
		m.log.Warn().Str("path", path).Str("op", opType).Str("host", ev.Event.Hostname).Msg("FIM ALERT FIRED")
	}
}

func isCriticalPath(path string) bool {
	for _, cp := range criticalPaths {
		if strings.HasPrefix(path, cp) || path == strings.TrimSuffix(cp, "/") {
			// Extra guard: /home/ matches are only for .ssh paths
			if cp == "/home/" && !strings.Contains(path, "/.ssh/") {
				continue
			}
			return true
		}
	}
	return false
}

func fimMitreIDs(path, op string) []string {
	switch {
	case strings.Contains(path, "sudoers") || strings.Contains(path, "passwd") || strings.Contains(path, "shadow"):
		return []string{"T1548.003", "T1003"}
	case strings.Contains(path, "cron") || strings.Contains(path, "init.d") || strings.Contains(path, "systemd"):
		return []string{"T1053.003", "T1543.002"}
	case strings.Contains(path, "authorized_keys") || strings.Contains(path, "sshd_config"):
		return []string{"T1098.004", "T1021.004"}
	case strings.Contains(path, "ld.so.preload"):
		return []string{"T1574.006"}
	default:
		return []string{"T1565.001"}
	}
}
