// pkg/types/events.go
// Canonical event types shared across all EDR monitors.
// Every event carries a full process context so analysts never lose attribution.

package types

import "time"

// ─── Severity ─────────────────────────────────────────────────────────────────

type Severity uint8

const (
	SeverityInfo     Severity = iota // 0 — telemetry only
	SeverityLow                      // 1
	SeverityMedium                   // 2
	SeverityHigh                     // 3
	SeverityCritical                 // 4
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// ─── EventType ────────────────────────────────────────────────────────────────

type EventType string

const (
	// Process lifecycle
	EventProcessExec   EventType = "PROCESS_EXEC"
	EventProcessExit   EventType = "PROCESS_EXIT"
	EventProcessFork   EventType = "PROCESS_FORK"
	EventProcessPtrace EventType = "PROCESS_PTRACE"

	// Network
	EventNetConnect   EventType = "NET_CONNECT"
	EventNetAccept    EventType = "NET_ACCEPT"
	EventNetDNS       EventType = "NET_DNS"
	EventNetClose     EventType = "NET_CLOSE"

	// File
	EventFileCreate EventType = "FILE_CREATE"
	EventFileWrite  EventType = "FILE_WRITE"
	EventFileDelete EventType = "FILE_DELETE"
	EventFileRename EventType = "FILE_RENAME"
	EventFileExec   EventType = "FILE_EXEC"
	EventFileChmod  EventType = "FILE_CHMOD"

	// Registry (Linux: critical config files)
	EventRegistrySet    EventType = "REG_SET"
	EventRegistryDelete EventType = "REG_DELETE"

	// Command activity
	EventCmdExec    EventType = "CMD_EXEC"
	EventCmdHistory EventType = "CMD_HISTORY"

	// Agent lifecycle
	EventAgentStart     EventType = "AGENT_START"
	EventAgentStop      EventType = "AGENT_STOP"
	EventAgentTamper    EventType = "AGENT_TAMPER"
	EventAgentHeartbeat EventType = "AGENT_HEARTBEAT"
)

// ─── ProcessContext ───────────────────────────────────────────────────────────
// Embedded in every event for full attribution.

type ProcessContext struct {
	PID         uint32   `json:"pid"`
	PPID        uint32   `json:"ppid"`
	TID         uint32   `json:"tid"`           // thread id
	UID         uint32   `json:"uid"`
	GID         uint32   `json:"gid"`
	EUID        uint32   `json:"euid"`          // effective uid (detects setuid escalation)
	Username    string   `json:"username"`
	Comm        string   `json:"comm"`          // short process name from kernel (max 16 chars)
	ExePath     string   `json:"exe_path"`      // resolved /proc/<pid>/exe
	Cmdline     string   `json:"cmdline"`       // full command line
	Cwd         string   `json:"cwd"`           // working directory
	Args        []string `json:"args"`
	Env         []string `json:"env,omitempty"` // captured only when suspicious
	StartTime   time.Time `json:"start_time"`
	ContainerID string   `json:"container_id,omitempty"` // if inside a container
	Namespace   string   `json:"namespace,omitempty"`    // PID namespace
}

// ─── Base Event ───────────────────────────────────────────────────────────────

type BaseEvent struct {
	ID        string         `json:"id"`         // UUID
	Type      EventType      `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	AgentID   string         `json:"agent_id"`
	Hostname  string         `json:"hostname"`
	Severity  Severity       `json:"severity"`
	Process   ProcessContext `json:"process"`
	Tags      []string       `json:"tags,omitempty"`
	RuleID    string         `json:"rule_id,omitempty"`    // set by detection engine
	AlertID   string         `json:"alert_id,omitempty"`   // set when alert generated
}

// ─── Process Events ───────────────────────────────────────────────────────────

// SocketInfo is a snapshot of one open socket from /proc/<pid>/fd at exec time.
type SocketInfo struct {
	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"` // "TCP" | "UDP"
	State    string `json:"state"`    // "ESTABLISHED" | "TIME_WAIT" | etc.
}

// NetworkTarget is a host/IP extracted from a process's command-line arguments.
type NetworkTarget struct {
	Raw      string `json:"raw"`             // original arg (URL or bare host)
	Host     string `json:"host"`            // extracted hostname / IP
	Port     uint16 `json:"port,omitempty"`  // extracted port (0 = unknown/default)
	Scheme   string `json:"scheme,omitempty"`// "http", "https", "ftp", etc.
}

type ProcessExecEvent struct {
	BaseEvent
	ParentProcess  ProcessContext  `json:"parent_process"`
	ExeHash        string          `json:"exe_hash"`        // SHA256 of the binary
	ExeSize        int64           `json:"exe_size"`
	Signed         bool            `json:"signed"`          // has valid signature (future)
	Interpreter    string          `json:"interpreter,omitempty"`
	ScriptPath     string          `json:"script_path,omitempty"`
	IsMemFD        bool            `json:"is_memfd"`
	IsDynamic      bool            `json:"is_dynamic"`
	Ancestry       []ProcessContext `json:"ancestry,omitempty"`
	// Network enrichment — populated at exec time from /proc/<pid>/fd + cmdline parsing.
	OpenSockets    []SocketInfo    `json:"open_sockets,omitempty"`
	NetworkTargets []NetworkTarget `json:"network_targets,omitempty"`
}

type ProcessExitEvent struct {
	BaseEvent
	ExitCode  int32         `json:"exit_code"`
	Signal    uint32        `json:"signal"`    // if killed by signal
	Duration  time.Duration `json:"duration"`  // wall time alive
	CPUUser   float64       `json:"cpu_user"`
	CPUSystem float64       `json:"cpu_system"`
}

type ProcessForkEvent struct {
	BaseEvent
	ChildPID  uint32 `json:"child_pid"`
	ChildTID  uint32 `json:"child_tid"`
	CloneFlags uint64 `json:"clone_flags"` // raw clone(2) flags
	IsThread  bool   `json:"is_thread"`   // CLONE_THREAD set → thread not process
}

type ProcessPtraceEvent struct {
	BaseEvent
	TargetPID    uint32 `json:"target_pid"`
	TargetComm   string `json:"target_comm"`
	PtraceRequest uint32 `json:"ptrace_request"` // PTRACE_ATTACH, PTRACE_PEEKDATA, etc.
}

// ─── Network Events ───────────────────────────────────────────────────────────

type NetworkProtocol string

const (
	ProtoTCP  NetworkProtocol = "TCP"
	ProtoUDP  NetworkProtocol = "UDP"
	ProtoICMP NetworkProtocol = "ICMP"
	ProtoRAW  NetworkProtocol = "RAW"
)

type NetworkDirection string

const (
	DirOutbound NetworkDirection = "OUTBOUND"
	DirInbound  NetworkDirection = "INBOUND"
)

type NetworkConnState string

const (
	ConnStateSYN         NetworkConnState = "SYN"
	ConnStateEstablished NetworkConnState = "ESTABLISHED"
	ConnStateCloseWait   NetworkConnState = "CLOSE_WAIT"
	ConnStateTimeWait    NetworkConnState = "TIME_WAIT"
	ConnStateClosed      NetworkConnState = "CLOSED"
	ConnStateReset       NetworkConnState = "RESET"
)

type NetworkEvent struct {
	BaseEvent
	SrcIP       string           `json:"src_ip"`
	SrcPort     uint16           `json:"src_port"`
	DstIP       string           `json:"dst_ip"`
	DstPort     uint16           `json:"dst_port"`
	Protocol    NetworkProtocol  `json:"protocol"`
	Direction   NetworkDirection `json:"direction"`
	State       NetworkConnState `json:"state"`
	BytesSent   uint64           `json:"bytes_sent"`
	BytesRecv   uint64           `json:"bytes_recv"`
	Duration    time.Duration    `json:"duration,omitempty"`
	DNSQuery    string           `json:"dns_query,omitempty"`    // resolved hostname if known
	GeoCountry  string           `json:"geo_country,omitempty"`
	IsPrivate   bool             `json:"is_private"`             // RFC1918 / loopback
	ThreatScore int              `json:"threat_score,omitempty"` // 0-100 from TI lookup
}

// ─── File Events ──────────────────────────────────────────────────────────────

type FileEvent struct {
	BaseEvent
	Path        string `json:"path"`
	OldPath     string `json:"old_path,omitempty"` // for renames
	HashBefore  string `json:"hash_before,omitempty"` // SHA256 before modification
	HashAfter   string `json:"hash_after,omitempty"`  // SHA256 after modification
	SizeBytes   int64  `json:"size_bytes"`
	Mode        uint32 `json:"mode"`       // file permissions
	INode       uint64 `json:"inode"`
	Device      uint64 `json:"device"`
	IsSymlink   bool   `json:"is_symlink"`
	IsHidden    bool   `json:"is_hidden"`  // starts with dot
}

// ─── Registry (Linux critical config) Events ─────────────────────────────────

type RegistryEvent struct {
	BaseEvent
	Path       string `json:"path"`         // watched file path
	Key        string `json:"key,omitempty"` // config key changed (best-effort parse)
	OldValue   string `json:"old_value,omitempty"`
	NewValue   string `json:"new_value,omitempty"`
	HashBefore string `json:"hash_before"`
	HashAfter  string `json:"hash_after"`
	Category   string `json:"category"` // e.g. "auth", "cron", "sudoers", "ssh", "ld"
}

// ─── Alert ────────────────────────────────────────────────────────────────────

type AlertStatus string

const (
	AlertOpen       AlertStatus = "OPEN"
	AlertInProgress AlertStatus = "IN_PROGRESS"
	AlertClosed     AlertStatus = "CLOSED"
	AlertFalsePos   AlertStatus = "FALSE_POSITIVE"
)

type Alert struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	Status      AlertStatus `json:"status"`
	RuleID      string      `json:"rule_id"`
	RuleName    string      `json:"rule_name"`
	MitreIDs    []string    `json:"mitre_ids"` // e.g. ["T1059.004", "T1055"]
	EventIDs    []string    `json:"event_ids"` // all events that triggered this
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	AgentID     string      `json:"agent_id"`
	Hostname    string      `json:"hostname"`
	Assignee    string      `json:"assignee,omitempty"`
	Notes       string      `json:"notes,omitempty"`
}

// ─── Event interface implementation ───────────────────────────────────────────
// BaseEvent implements the events.Event interface so all event structs that
// embed BaseEvent automatically satisfy it without needing external adapters.

func (e *BaseEvent) EventType() string { return string(e.Type) }
func (e *BaseEvent) EventID() string   { return e.ID }
