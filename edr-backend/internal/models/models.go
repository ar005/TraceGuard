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
	ID        string    `db:"id"         json:"id"`
	Hostname  string    `db:"hostname"   json:"hostname"`
	OS        string    `db:"os"         json:"os"`
	OSVersion string    `db:"os_version" json:"os_version"`
	IP        string    `db:"ip"         json:"ip"`
	AgentVer  string    `db:"agent_ver"  json:"agent_ver"`
	FirstSeen time.Time `db:"first_seen" json:"first_seen"`
	LastSeen  time.Time `db:"last_seen"  json:"last_seen"`
	IsOnline  bool      `db:"is_online"  json:"is_online"`
	ConfigVer string    `db:"config_ver" json:"config_ver"`
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
	Author      string          `db:"author"      json:"author"`
}

// RuleCondition is a single condition in a rule's condition list.
type RuleCondition struct {
	Field string      `json:"field"` // e.g. "process.comm", "dst_port"
	Op    string      `json:"op"`    // eq, ne, in, gt, lt, startswith, regex
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
