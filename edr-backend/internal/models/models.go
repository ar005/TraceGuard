// internal/models/models.go
// Database row types used with sqlx scanning.

package models

import (
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

// Agent represents a registered endpoint agent.
type Agent struct {
	ID        string         `db:"id"         json:"id"`
	Hostname  string         `db:"hostname"   json:"hostname"`
	OS        string         `db:"os"         json:"os"`
	OSVersion string         `db:"os_version" json:"os_version"`
	IP        string         `db:"ip"         json:"ip"`
	AgentVer  string         `db:"agent_ver"  json:"agent_ver"`
	FirstSeen time.Time      `db:"first_seen" json:"first_seen"`
	LastSeen  time.Time      `db:"last_seen"  json:"last_seen"`
	IsOnline  bool           `db:"is_online"  json:"is_online"`
	ConfigVer string         `db:"config_ver" json:"config_ver"`
	Tags      pq.StringArray `db:"tags"       json:"tags"`
	Env       string         `db:"env"        json:"env"`
	Notes     string         `db:"notes"      json:"notes"`
}

// Event represents a stored security event.
type Event struct {
	ID         string          `db:"id"          json:"id"`
	AgentID    string          `db:"agent_id"    json:"agent_id"`
	Hostname   string          `db:"hostname"    json:"hostname"`
	EventType  string          `db:"event_type"  json:"event_type"`
	Timestamp  time.Time       `db:"timestamp"   json:"timestamp"`
	Payload    json.RawMessage `db:"payload"     json:"payload"`
	ReceivedAt time.Time       `db:"received_at" json:"received_at"`
	Severity   int16           `db:"severity"    json:"severity"`
	RuleID     string          `db:"rule_id"     json:"rule_id"`
	AlertID    string          `db:"alert_id"    json:"alert_id"`
}

// Alert represents a security alert.
type Alert struct {
	ID          string         `db:"id"          json:"id"`
	Title       string         `db:"title"       json:"title"`
	Description string         `db:"description" json:"description"`
	Severity    int16          `db:"severity"    json:"severity"`
	Status      string         `db:"status"      json:"status"`
	RuleID      string         `db:"rule_id"     json:"rule_id"`
	RuleName    string         `db:"rule_name"   json:"rule_name"`
	MitreIDs    pq.StringArray `db:"mitre_ids"   json:"mitre_ids"`
	EventIDs    pq.StringArray `db:"event_ids"   json:"event_ids"`
	AgentID     string         `db:"agent_id"    json:"agent_id"`
	Hostname    string         `db:"hostname"    json:"hostname"`
	FirstSeen   time.Time      `db:"first_seen"  json:"first_seen"`
	LastSeen    time.Time      `db:"last_seen"   json:"last_seen"`
	Assignee    string         `db:"assignee"    json:"assignee"`
	Notes       string         `db:"notes"       json:"notes"`
	HitCount    int64          `db:"hit_count"   json:"hit_count"`
	IncidentID  string         `db:"incident_id" json:"incident_id"`
}

// Rule represents a detection rule.
type Rule struct {
	ID          string          `db:"id"          json:"id"`
	Name        string          `db:"name"        json:"name"`
	Description string          `db:"description" json:"description"`
	Enabled     bool            `db:"enabled"     json:"enabled"`
	Severity    int16           `db:"severity"    json:"severity"`
	EventTypes  pq.StringArray  `db:"event_types" json:"event_types"`
	Conditions  json.RawMessage `db:"conditions"  json:"conditions"`
	MitreIDs    pq.StringArray  `db:"mitre_ids"   json:"mitre_ids"`
	CreatedAt   time.Time       `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at"  json:"updated_at"`
	Author             string          `db:"author"              json:"author"`
	RuleType           string          `db:"rule_type"           json:"rule_type"`
	ThresholdCount     int             `db:"threshold_count"     json:"threshold_count"`
	ThresholdWindowS   int             `db:"threshold_window_s"  json:"threshold_window_s"`
	GroupBy            string          `db:"group_by"            json:"group_by"`
}

// SuppressionRule silences events that match its conditions before detection runs.
// Use it to filter known-good noise (automated tasks, deploy pipelines, etc.)
// so analysts don't drown in false positives.
type SuppressionRule struct {
	ID          string          `db:"id"          json:"id"`
	Name        string          `db:"name"        json:"name"`
	Description string          `db:"description" json:"description"`
	Enabled     bool            `db:"enabled"     json:"enabled"`
	EventTypes  pq.StringArray  `db:"event_types" json:"event_types"`
	Conditions  json.RawMessage `db:"conditions"  json:"conditions"`
	CreatedAt   time.Time       `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at"  json:"updated_at"`
	Author      string          `db:"author"      json:"author"`
	HitCount    int64           `db:"hit_count"   json:"hit_count"`
	LastHitAt   *time.Time      `db:"last_hit_at" json:"last_hit_at,omitempty"`
}

// Incident groups related alerts into a single investigation unit.
type Incident struct {
	ID          string         `db:"id"          json:"id"`
	Title       string         `db:"title"       json:"title"`
	Description string         `db:"description" json:"description"`
	Severity    int16          `db:"severity"    json:"severity"`
	Status      string         `db:"status"      json:"status"`     // OPEN, INVESTIGATING, CLOSED
	AlertIDs    pq.StringArray `db:"alert_ids"   json:"alert_ids"`
	AgentIDs    pq.StringArray `db:"agent_ids"   json:"agent_ids"`
	Hostnames   pq.StringArray `db:"hostnames"   json:"hostnames"`
	MitreIDs    pq.StringArray `db:"mitre_ids"   json:"mitre_ids"`
	AlertCount  int            `db:"alert_count" json:"alert_count"`
	FirstSeen   time.Time      `db:"first_seen"  json:"first_seen"`
	LastSeen    time.Time      `db:"last_seen"   json:"last_seen"`
	Assignee    string         `db:"assignee"    json:"assignee"`
	Notes       string         `db:"notes"       json:"notes"`
	CreatedAt   time.Time      `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"  json:"updated_at"`
}

// AgentPackage represents an installed package on an endpoint.
type AgentPackage struct {
	ID          int64     `db:"id" json:"id"`
	AgentID     string    `db:"agent_id" json:"agent_id"`
	Name        string    `db:"name" json:"name"`
	Version     string    `db:"version" json:"version"`
	Arch        string    `db:"arch" json:"arch"`
	CollectedAt time.Time `db:"collected_at" json:"collected_at"`
}

// Vulnerability represents a detected CVE for an installed package.
type Vulnerability struct {
	ID             int64     `db:"id" json:"id"`
	AgentID        string    `db:"agent_id" json:"agent_id"`
	PackageName    string    `db:"package_name" json:"package_name"`
	PackageVersion string    `db:"package_version" json:"package_version"`
	CveID          string    `db:"cve_id" json:"cve_id"`
	Severity       string    `db:"severity" json:"severity"`
	Description    string    `db:"description" json:"description"`
	FixedVersion   string    `db:"fixed_version" json:"fixed_version"`
	DetectedAt     time.Time `db:"detected_at" json:"detected_at"`
}

// VulnStats holds vulnerability counts by severity for an agent.
type VulnStats struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
	Total    int64 `json:"total"`
}

// IOC represents an Indicator of Compromise for threat intelligence matching.
type IOC struct {
	ID          string     `db:"id"          json:"id"`
	Type        string     `db:"type"        json:"type"`        // "ip", "domain", "hash_sha256", "hash_md5"
	Value       string     `db:"value"       json:"value"`       // the indicator value (normalized lowercase)
	Source      string     `db:"source"      json:"source"`      // feed name or "manual"
	Severity    int16      `db:"severity"    json:"severity"`    // 0-4 matching alert severity scale
	Description string     `db:"description" json:"description"`
	Tags        pq.StringArray `db:"tags"    json:"tags"`
	Enabled     bool       `db:"enabled"     json:"enabled"`
	ExpiresAt   *time.Time `db:"expires_at"  json:"expires_at,omitempty"`
	CreatedAt   time.Time  `db:"created_at"  json:"created_at"`
	HitCount    int64      `db:"hit_count"   json:"hit_count"`
	LastHitAt   *time.Time `db:"last_hit_at" json:"last_hit_at,omitempty"`
}

// IOCStats holds IOC counts by type.
type IOCStats struct {
	TotalIOCs    int64 `db:"total_iocs"    json:"total_iocs"`
	IPCount      int64 `db:"ip_count"      json:"ip_count"`
	DomainCount  int64 `db:"domain_count"  json:"domain_count"`
	HashCount    int64 `db:"hash_count"    json:"hash_count"`
	EnabledCount int64 `db:"enabled_count" json:"enabled_count"`
	TotalHits    int64 `db:"total_hits"    json:"total_hits"`
}

// IOCSourceStats holds per-source IOC statistics.
type IOCSourceStats struct {
	Source       string    `db:"source"        json:"source"`
	Total        int64     `db:"total"         json:"total"`
	IPCount      int64     `db:"ip_count"      json:"ip_count"`
	DomainCount  int64     `db:"domain_count"  json:"domain_count"`
	HashCount    int64     `db:"hash_count"    json:"hash_count"`
	EnabledCount int64     `db:"enabled_count" json:"enabled_count"`
	TotalHits    int64     `db:"total_hits"    json:"total_hits"`
	FirstSeen    time.Time `db:"first_seen"    json:"first_seen"`
	LastUpdated  time.Time `db:"last_updated"  json:"last_updated"`
}

// BacktestResult is returned by the rule backtest endpoint.
type BacktestResult struct {
	RuleID       string  `json:"rule_id"`
	TotalScanned int     `json:"total_scanned"`
	Matched      int     `json:"matched"`
	MatchRate    float64 `json:"match_rate"`
	WindowHours  int     `json:"window_hours"`
	Samples      []Event `json:"samples"` // up to 5 matching events
}

// RuleCondition is a single condition in a rule's condition list.
type RuleCondition struct {
	Field string      `json:"field"` // e.g. "process.comm", "dst_port"
	Op    string      `json:"op"`    // eq, ne, in, gt, lt, startswith, contains, regex
	Value interface{} `json:"value"`
}

// SeverityLabel returns a human-readable severity label.
func SeverityLabel(s int16) string {
	switch s {
	case 0:
		return "INFO"
	case 1:
		return "LOW"
	case 2:
		return "MEDIUM"
	case 3:
		return "HIGH"
	case 4:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
