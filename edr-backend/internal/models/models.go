// internal/models/models.go
// Database row types used with sqlx scanning.

package models

import (
	"encoding/json"
	"net"
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
	Tags           pq.StringArray  `db:"tags"             json:"tags"`
	Env            string          `db:"env"              json:"env"`
	Notes          string          `db:"notes"            json:"notes"`
	WinEventConfig  json.RawMessage `db:"winevent_config"   json:"winevent_config,omitempty"`
	RiskScore       int16           `db:"risk_score"        json:"risk_score"`
	RiskFactors     json.RawMessage `db:"risk_factors"      json:"risk_factors,omitempty"`
	RiskUpdatedAt   *time.Time      `db:"risk_updated_at"   json:"risk_updated_at,omitempty"`
}

// Event represents a stored security event.
type Event struct {
	ID          string          `db:"id"           json:"id"`
	AgentID     string          `db:"agent_id"     json:"agent_id"`
	Hostname    string          `db:"hostname"     json:"hostname"`
	EventType   string          `db:"event_type"   json:"event_type"`
	Timestamp   time.Time       `db:"timestamp"    json:"timestamp"`
	Payload     json.RawMessage `db:"payload"      json:"payload"`
	ReceivedAt  time.Time       `db:"received_at"  json:"received_at"`
	Severity    int16           `db:"severity"     json:"severity"`
	RuleID      string          `db:"rule_id"      json:"rule_id"`
	AlertID     string          `db:"alert_id"     json:"alert_id"`
	ClassUID    int             `db:"class_uid"    json:"class_uid,omitempty"`
	CategoryUID int16           `db:"category_uid" json:"category_uid,omitempty"`
	ActivityID  int16           `db:"activity_id"  json:"activity_id,omitempty"`
	SourceType  string          `db:"source_type"  json:"source_type,omitempty"`
	SourceID    string          `db:"source_id"    json:"source_id,omitempty"`
	TenantID    string          `db:"tenant_id"    json:"tenant_id,omitempty"`
	UserUID     string          `db:"user_uid"     json:"user_uid,omitempty"`
	SrcIP       *string         `db:"src_ip"       json:"src_ip,omitempty"`
	DstIP       *string         `db:"dst_ip"       json:"dst_ip,omitempty"`
	ProcessName string          `db:"process_name" json:"process_name,omitempty"`
	RawLog      string          `db:"raw_log"      json:"raw_log,omitempty"`
	Enrichments json.RawMessage `db:"enrichments"  json:"enrichments,omitempty"`
}

// Alert represents a security alert.
type Alert struct {
	ID          string         `db:"id"           json:"id"`
	TenantID    string         `db:"tenant_id"    json:"tenant_id,omitempty"`
	Title       string         `db:"title"        json:"title"`
	Description string         `db:"description"  json:"description"`
	Severity    int16          `db:"severity"     json:"severity"`
	Status      string         `db:"status"       json:"status"`
	RuleID      string         `db:"rule_id"      json:"rule_id"`
	RuleName    string         `db:"rule_name"    json:"rule_name"`
	MitreIDs    pq.StringArray `db:"mitre_ids"    json:"mitre_ids"`
	EventIDs    pq.StringArray `db:"event_ids"    json:"event_ids"`
	AgentID     string         `db:"agent_id"     json:"agent_id"`
	Hostname    string         `db:"hostname"     json:"hostname"`
	FirstSeen   time.Time      `db:"first_seen"   json:"first_seen"`
	LastSeen    time.Time      `db:"last_seen"    json:"last_seen"`
	Assignee    string         `db:"assignee"     json:"assignee"`
	Notes       string         `db:"notes"        json:"notes"`
	HitCount    int64          `db:"hit_count"    json:"hit_count"`
	IncidentID  string         `db:"incident_id"  json:"incident_id"`
	// XDR Phase 2 — cross-source identity correlation
	UserUID     string         `db:"user_uid"     json:"user_uid"`
	SourceTypes pq.StringArray `db:"source_types" json:"source_types"`
	SrcIP       string         `db:"src_ip"       json:"src_ip,omitempty"`
	// Phase 5 — AI triage
	TriageVerdict string     `db:"triage_verdict" json:"triage_verdict,omitempty"`
	TriageScore   int16      `db:"triage_score"   json:"triage_score,omitempty"`
	TriageNotes   string          `db:"triage_notes"   json:"triage_notes,omitempty"`
	TriageAt      *time.Time      `db:"triage_at"      json:"triage_at,omitempty"`
	Enrichments   json.RawMessage `db:"enrichments"    json:"enrichments,omitempty"`
	RiskScore     int16           `db:"risk_score"     json:"risk_score"`
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
	SequenceSteps      *json.RawMessage `db:"sequence_steps"      json:"sequence_steps,omitempty"`
	SequenceWindowS    int             `db:"sequence_window_s"   json:"sequence_window_s"`
	SequenceBy         string          `db:"sequence_by"         json:"sequence_by"`
	SourceTypes        pq.StringArray  `db:"source_types"        json:"source_types"`
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
	ID          string         `db:"id"           json:"id"`
	TenantID    string         `db:"tenant_id"    json:"tenant_id,omitempty"`
	Title       string         `db:"title"        json:"title"`
	Description string         `db:"description"  json:"description"`
	Severity    int16          `db:"severity"     json:"severity"`
	Status      string         `db:"status"       json:"status"`
	AlertIDs    pq.StringArray `db:"alert_ids"    json:"alert_ids"`
	AgentIDs    pq.StringArray `db:"agent_ids"    json:"agent_ids"`
	Hostnames   pq.StringArray `db:"hostnames"    json:"hostnames"`
	MitreIDs    pq.StringArray `db:"mitre_ids"    json:"mitre_ids"`
	AlertCount  int            `db:"alert_count"  json:"alert_count"`
	FirstSeen   time.Time      `db:"first_seen"   json:"first_seen"`
	LastSeen    time.Time      `db:"last_seen"    json:"last_seen"`
	Assignee    string         `db:"assignee"     json:"assignee"`
	Notes       string         `db:"notes"        json:"notes"`
	CreatedAt   time.Time      `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"   json:"updated_at"`
	// XDR Phase 2 — cross-source identity correlation
	UserUIDs    pq.StringArray `db:"user_uids"    json:"user_uids"`
	SrcIPs      pq.StringArray `db:"src_ips"      json:"src_ips"`
	SourceTypes pq.StringArray `db:"source_types" json:"source_types"`
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


// YARARule is a YARA signature stored in the database.
// Agents pull all enabled rules and scan files/memory locally.
type YARARule struct {
	ID          string         `db:"id"          json:"id"`
	Name        string         `db:"name"        json:"name"`
	Description string         `db:"description" json:"description"`
	RuleText    string         `db:"rule_text"   json:"rule_text"`
	Enabled     bool           `db:"enabled"     json:"enabled"`
	Severity    int16          `db:"severity"    json:"severity"`
	MitreIDs    pq.StringArray `db:"mitre_ids"   json:"mitre_ids"`
	Tags        pq.StringArray `db:"tags"        json:"tags"`
	Author      string         `db:"author"      json:"author"`
	CreatedAt   time.Time      `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"  json:"updated_at"`
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

// CVEDetail represents a cached CVE record from NVD or other source.
type CVEDetail struct {
	CVEID            string         `db:"cve_id"            json:"cve_id"`
	Severity         string         `db:"severity"          json:"severity"`
	Description      string         `db:"description"       json:"description"`
	PublishedDate    *time.Time     `db:"published_date"    json:"published_date,omitempty"`
	References       pq.StringArray `db:"references"        json:"references"`
	ExploitAvailable bool           `db:"exploit_available" json:"exploit_available"`
	CisaKEV          bool           `db:"cisa_kev"          json:"cisa_kev"`
	Source           string         `db:"source"            json:"source"`
	FetchedAt        time.Time      `db:"fetched_at"        json:"fetched_at"`
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

// SequenceStep is one step in a sequence or sequence_cross detection rule.
// SourceTypes restricts this step to events from specific source categories.
type SequenceStep struct {
	EventType   string   `json:"event_type"`
	SourceTypes []string `json:"source_types,omitempty"` // empty = any
	Conditions  []RuleCondition `json:"conditions,omitempty"`
	MaxDelayS   int      `json:"max_delay_s,omitempty"`
}

// ─── XDR types ────────────────────────────────────────────────────────────────

// XdrEvent is the normalized event envelope flowing through the NATS pipeline.
// It embeds Event so all existing detection engine field access is unchanged.
// New fields map to OCSF (Open Cybersecurity Schema Framework) for cross-source
// interoperability. See §2.2 of xdr.md for column mappings.
type XdrEvent struct {
	Event                           // existing endpoint event (zero-copy embed)
	ClassUID    int             `db:"class_uid"    json:"class_uid"`    // OCSF class
	CategoryUID int16           `db:"category_uid" json:"category_uid"` // OCSF category
	ActivityID  int16           `db:"activity_id"  json:"activity_id"`  // OCSF activity
	SourceType  string          `db:"source_type"  json:"source_type"`  // endpoint|network|cloud|identity|email|saas
	SourceID    string          `db:"source_id"    json:"source_id"`    // xdr_sources.id
	TenantID    string          `db:"tenant_id"    json:"tenant_id"`    // multi-tenancy (Phase 4)
	UserUID     string          `db:"user_uid"     json:"user_uid"`     // canonical identity (email/UPN)
	SrcIP       *net.IP         `db:"src_ip"       json:"src_ip,omitempty"`
	DstIP       *net.IP         `db:"dst_ip"       json:"dst_ip,omitempty"`
	ProcessName string          `db:"process_name" json:"process_name"`
	RawLog      string          `db:"raw_log"      json:"raw_log"`      // original connector log line
	Enrichments json.RawMessage `db:"enrichments"  json:"enrichments"`  // {geo, threat_intel, ...}
	// Network flow fields (populated for NETWORK_CONNECTION events)
	DstPort  int    `db:"-" json:"dst_port,omitempty"`
	BytesOut uint64 `db:"-" json:"bytes_out,omitempty"`
}

// XdrSource maps to the xdr_sources table — connector registry.
type XdrSource struct {
	ID          string          `db:"id"           json:"id"`
	Name        string          `db:"name"         json:"name"`
	SourceType  string          `db:"source_type"  json:"source_type"`
	Connector   string          `db:"connector"    json:"connector"`
	Config      json.RawMessage `db:"config"       json:"config"`
	Enabled     bool            `db:"enabled"      json:"enabled"`
	LastSeenAt  *time.Time      `db:"last_seen_at" json:"last_seen_at,omitempty"`
	EventsToday int64           `db:"events_today" json:"events_today"`
	ErrorState  string          `db:"error_state"  json:"error_state"`
	CreatedAt   time.Time       `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at"   json:"updated_at"`
}


// ── SOAR / Playbooks ──────────────────────────────────────────────────────────

// PlaybookAction is one step in a playbook action chain.
type PlaybookAction struct {
	Type   string          `json:"type"`   // slack|pagerduty|email|isolate_host|block_ip|update_alert|run_hunt|webhook
	Config json.RawMessage `json:"config"` // action-specific parameters
}

// PlaybookTriggerFilter specifies which alerts/events activate the playbook.
type PlaybookTriggerFilter struct {
	MinSeverity  int16    `json:"min_severity,omitempty"`
	RuleIDs      []string `json:"rule_ids,omitempty"`
	EventTypes   []string `json:"event_types,omitempty"`
	SourceTypes  []string `json:"source_types,omitempty"`
}

// Playbook is a SOAR automation rule stored in the playbooks table.
type Playbook struct {
	ID            string          `db:"id"             json:"id"`
	Name          string          `db:"name"           json:"name"`
	Description   string          `db:"description"    json:"description"`
	Enabled       bool            `db:"enabled"        json:"enabled"`
	TriggerType   string          `db:"trigger_type"   json:"trigger_type"` // alert|xdr_event
	TriggerFilter json.RawMessage `db:"trigger_filter" json:"trigger_filter"`
	Actions       json.RawMessage `db:"actions"        json:"actions"`
	RunCount      int64           `db:"run_count"      json:"run_count"`
	LastRunAt     *time.Time      `db:"last_run_at"    json:"last_run_at,omitempty"`
	CreatedAt     time.Time       `db:"created_at"     json:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at"     json:"updated_at"`
	CreatedBy     string          `db:"created_by"     json:"created_by"`
}

// PlaybookRun is an execution record stored in playbook_runs.
type PlaybookRun struct {
	ID           string          `db:"id"            json:"id"`
	PlaybookID   string          `db:"playbook_id"   json:"playbook_id"`
	PlaybookName string          `db:"playbook_name" json:"playbook_name"`
	TriggerType  string          `db:"trigger_type"  json:"trigger_type"`
	TriggerID    string          `db:"trigger_id"    json:"trigger_id"`
	Status       string          `db:"status"        json:"status"` // running|success|failed
	StartedAt    time.Time       `db:"started_at"    json:"started_at"`
	FinishedAt   *time.Time      `db:"finished_at"   json:"finished_at,omitempty"`
	ActionsLog   json.RawMessage `db:"actions_log"   json:"actions_log"`
	TriggeredBy  string          `db:"triggered_by"  json:"triggered_by"`
	Error        string          `db:"error"         json:"error"`
}

// ExportDestination is a SIEM/notification sink.
type ExportDestination struct {
	ID          string          `db:"id"           json:"id"`
	Name        string          `db:"name"         json:"name"`
	DestType    string          `db:"dest_type"    json:"dest_type"` // slack|pagerduty|webhook|syslog_cef|email
	Config      json.RawMessage `db:"config"       json:"config"`
	Enabled     bool            `db:"enabled"      json:"enabled"`
	FilterSev   int16           `db:"filter_sev"   json:"filter_sev"`
	FilterTypes pq.StringArray  `db:"filter_types" json:"filter_types"`
	CreatedAt   time.Time       `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at"   json:"updated_at"`
}

// ── Case Management (Phase 4) ──────────────────────────────────────────────

// CaseStatus values
const (
	CaseStatusOpen         = "OPEN"
	CaseStatusInvestigating = "INVESTIGATING"
	CaseStatusContained    = "CONTAINED"
	CaseStatusResolved     = "RESOLVED"
	CaseStatusClosed       = "CLOSED"
)

type Case struct {
	ID          string         `db:"id"          json:"id"`
	TenantID    string         `db:"tenant_id"   json:"tenant_id,omitempty"`
	Title       string         `db:"title"       json:"title"`
	Description string         `db:"description" json:"description"`
	Status      string         `db:"status"      json:"status"`
	Severity    int16          `db:"severity"    json:"severity"`
	Assignee    string         `db:"assignee"    json:"assignee"`
	Tags        pq.StringArray `db:"tags"        json:"tags"`
	MitreIDs    pq.StringArray `db:"mitre_ids"   json:"mitre_ids"`
	AlertCount  int            `db:"alert_count" json:"alert_count"`
	CreatedBy   string         `db:"created_by"  json:"created_by"`
	CreatedAt   time.Time      `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"  json:"updated_at"`
	ClosedAt    *time.Time     `db:"closed_at"   json:"closed_at,omitempty"`
}

type CaseNote struct {
	ID        string    `db:"id"         json:"id"`
	CaseID    string    `db:"case_id"    json:"case_id"`
	Body      string    `db:"body"       json:"body"`
	Author    string    `db:"author"     json:"author"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type CaseAlert struct {
	CaseID    string    `db:"case_id"   json:"case_id"`
	AlertID   string    `db:"alert_id"  json:"alert_id"`
	LinkedAt  time.Time `db:"linked_at" json:"linked_at"`
	LinkedBy  string    `db:"linked_by" json:"linked_by"`
}

// IdentityRecord maps to identity_graph — normalized cross-source user identity.
type IdentityRecord struct {
	ID           string          `db:"id"            json:"id"`
	CanonicalUID string          `db:"canonical_uid" json:"canonical_uid"` // normalized lowercase email/UPN
	DisplayName  string          `db:"display_name"  json:"display_name"`
	Email        string          `db:"email"         json:"email"`
	Department   string          `db:"department"    json:"department"`
	AccountIDs   json.RawMessage `db:"account_ids"   json:"account_ids"` // {"okta":"...","ad":"..."}
	Aliases      pq.StringArray  `db:"aliases"       json:"aliases"`     // alternate UIDs that map to this record
	RiskScore    int16           `db:"risk_score"    json:"risk_score"`  // 0–100
	RiskFactors  json.RawMessage `db:"risk_factors"  json:"risk_factors"`
	IsPrivileged bool            `db:"is_privileged" json:"is_privileged"`
	AgentIDs     pq.StringArray  `db:"agent_ids"     json:"agent_ids"`
	LastLoginAt  *time.Time      `db:"last_login_at" json:"last_login_at,omitempty"`
	LastLoginIP  string          `db:"last_seen_src" json:"last_login_ip"` // maps to last_seen_src column
	UpdatedAt    time.Time       `db:"updated_at"    json:"updated_at"`
}

// PendingCommand is a queued command waiting for an agent to come online.
type PendingCommand struct {
	ID         string          `db:"id"          json:"id"`
	AgentID    string          `db:"agent_id"    json:"agent_id"`
	Action     string          `db:"action"      json:"action"`
	Args       json.RawMessage `db:"args"        json:"args"`
	CreatedBy  string          `db:"created_by"  json:"created_by"`
	CreatedAt  time.Time       `db:"created_at"  json:"created_at"`
	Status     string          `db:"status"      json:"status"` // pending, executed, failed, cancelled
	Result     json.RawMessage `db:"result"      json:"result,omitempty"`
	ExecutedAt *time.Time      `db:"executed_at" json:"executed_at,omitempty"`
}

// AssetRecord maps to the asset_inventory table (populated in XDR Phase 2).
type AssetRecord struct {
	ID              string         `db:"id"               json:"id"`
	AssetType       string         `db:"asset_type"       json:"asset_type"`   // endpoint|server|container|vm|network_device|cloud_resource
	Hostname        string         `db:"hostname"         json:"hostname"`
	IPAddresses     pq.StringArray `db:"ip_addresses"     json:"ip_addresses"`
	MACAddresses    pq.StringArray `db:"mac_addresses"    json:"mac_addresses"`
	OS              string         `db:"os"               json:"os"`
	OSVersion       string         `db:"os_version"       json:"os_version"`
	CloudProvider   string         `db:"cloud_provider"   json:"cloud_provider"` // aws|azure|gcp|""
	CloudRegion     string         `db:"cloud_region"     json:"cloud_region"`
	CloudAccount    string         `db:"cloud_account"    json:"cloud_account"`
	CloudResourceID string         `db:"cloud_resource_id" json:"cloud_resource_id"`
	AgentID         string         `db:"agent_id"         json:"agent_id"`
	Tags            pq.StringArray `db:"tags"             json:"tags"`
	RiskScore       int16          `db:"risk_score"       json:"risk_score"`
	Criticality     int16          `db:"criticality"      json:"criticality"` // 1=low … 4=critical
	OwnerUID        string         `db:"owner_uid"        json:"owner_uid"`
	FirstSeenAt     time.Time      `db:"first_seen_at"    json:"first_seen_at"`
	LastSeenAt      time.Time      `db:"last_seen_at"     json:"last_seen_at"`
	SourceID        string         `db:"source_id"        json:"source_id"`
}

// LoginEvent is used by the user risk scorer to represent a login attempt.
type LoginEvent struct {
	UserUID   string
	SrcIP     string
	Timestamp time.Time
	Success   bool
	Provider  string // "okta" | "ad" | "saml" | ...
}

// ResponseAction maps to the response_actions table — SOAR action audit trail.
type ResponseAction struct {
	ID             string          `db:"id"              json:"id"`
	ActionType     string          `db:"action_type"     json:"action_type"`
	TargetType     string          `db:"target_type"     json:"target_type"`
	TargetID       string          `db:"target_id"       json:"target_id"`
	Status         string          `db:"status"          json:"status"`
	TriggeredBy    string          `db:"triggered_by"    json:"triggered_by"`
	PlaybookRunID  string          `db:"playbook_run_id" json:"playbook_run_id"`
	Params         json.RawMessage `db:"params"          json:"params"`
	Result         json.RawMessage `db:"result"          json:"result"`
	CreatedAt      time.Time       `db:"created_at"      json:"created_at"`
	ReversedAt     *time.Time      `db:"reversed_at"     json:"reversed_at,omitempty"`
	ReversedBy     string          `db:"reversed_by"     json:"reversed_by"`
	Notes          string          `db:"notes"           json:"notes"`
}

// LateralHit is returned by the lateral movement DB sweep.
type LateralHit struct {
	UserUID    string
	TenantID   string
	AgentCount int
	AgentIDs   []string
	Hostnames  []string
}

// LoginSession tracks individual user login/logout events.
type LoginSession struct {
	ID          string     `db:"id"           json:"id"`
	TenantID    string     `db:"tenant_id"    json:"tenant_id"`
	UserUID     string     `db:"user_uid"     json:"user_uid"`
	AgentID     string     `db:"agent_id"     json:"agent_id"`
	SrcIP       *string    `db:"src_ip"       json:"src_ip,omitempty"`
	Hostname    string     `db:"hostname"     json:"hostname"`
	LoggedInAt  time.Time  `db:"logged_in_at" json:"logged_in_at"`
	LoggedOutAt *time.Time `db:"logged_out_at" json:"logged_out_at,omitempty"`
	DurationS   *int       `db:"duration_s"   json:"duration_s,omitempty"`
	EventID     string     `db:"event_id"     json:"event_id"`
	CreatedAt   time.Time  `db:"created_at"   json:"created_at"`
}

// AutoRemediationRule triggers an automated action when a matching alert fires.
type AutoRemediationRule struct {
	ID           string    `db:"id"            json:"id"`
	TenantID     string    `db:"tenant_id"     json:"tenant_id"`
	Name         string    `db:"name"          json:"name"`
	TriggerType  string    `db:"trigger_type"  json:"trigger_type"`  // rule_id | mitre_id | severity
	TriggerValue string    `db:"trigger_value" json:"trigger_value"`
	Action       string    `db:"action"        json:"action"` // isolate_host | kill_process | block_user | run_playbook
	PlaybookID   string    `db:"playbook_id"   json:"playbook_id"`
	MinSeverity  int       `db:"min_severity"  json:"min_severity"`
	Enabled      bool      `db:"enabled"       json:"enabled"`
	CreatedAt    time.Time `db:"created_at"    json:"created_at"`
}

// CustomIOCFeed is a user-defined external IOC feed.
type CustomIOCFeed struct {
	ID           string     `db:"id"             json:"id"`
	TenantID     string     `db:"tenant_id"      json:"tenant_id"`
	Name         string     `db:"name"           json:"name"`
	URL          string     `db:"url"            json:"url"`
	Format       string     `db:"format"         json:"format"`    // txt | csv | stix
	FeedType     string     `db:"feed_type"      json:"feed_type"` // ip | domain | hash
	Enabled      bool       `db:"enabled"        json:"enabled"`
	LastSyncedAt *time.Time `db:"last_synced_at" json:"last_synced_at"`
	EntryCount   int        `db:"entry_count"    json:"entry_count"`
	CreatedAt    time.Time  `db:"created_at"     json:"created_at"`
}

// AutoCasePolicy defines criteria for automatic case creation from alerts.
type AutoCasePolicy struct {
	ID          string         `db:"id"           json:"id"`
	TenantID    string         `db:"tenant_id"    json:"tenant_id"`
	Name        string         `db:"name"         json:"name"`
	MinSeverity int16          `db:"min_severity" json:"min_severity"`
	RuleIDs     pq.StringArray `db:"rule_ids"     json:"rule_ids"`
	MitreIDs    pq.StringArray `db:"mitre_ids"    json:"mitre_ids"`
	Enabled     bool           `db:"enabled"      json:"enabled"`
	CreatedAt   time.Time      `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"   json:"updated_at"`
}
