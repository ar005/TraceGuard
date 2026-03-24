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

	// Authentication
	EventLoginSuccess EventType = "LOGIN_SUCCESS"
	EventLoginFailed  EventType = "LOGIN_FAILED"
	EventSudoExec     EventType = "SUDO_EXEC"

	// Agent lifecycle
	EventAgentStart     EventType = "AGENT_START"
	EventAgentStop      EventType = "AGENT_STOP"
	EventAgentTamper    EventType = "AGENT_TAMPER"
	EventAgentHeartbeat EventType = "AGENT_HEARTBEAT"

	// Vulnerability / package inventory
	EventPkgInventory EventType = "PKG_INVENTORY"

	// Browser monitoring (from extension)
	EventBrowserRequest EventType = "BROWSER_REQUEST"

	// Kernel module monitoring
	EventKernelModuleLoad   EventType = "KERNEL_MODULE_LOAD"
	EventKernelModuleUnload EventType = "KERNEL_MODULE_UNLOAD"

	// USB device monitoring
	EventUSBConnect    EventType = "USB_CONNECT"
	EventUSBDisconnect EventType = "USB_DISCONNECT"

	// Named pipe monitoring
	EventPipeCreate EventType = "PIPE_CREATE"

	// Network share monitoring
	EventShareMount   EventType = "SHARE_MOUNT"
	EventShareUnmount EventType = "SHARE_UNMOUNT"

	// Memory injection detection
	EventMemoryInject EventType = "MEMORY_INJECT"

	// Cron/scheduled task monitoring
	EventCronModify EventType = "CRON_MODIFY"
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
	Runtime     string   `json:"runtime,omitempty"`      // docker, containerd, podman, cri-o
	ImageName   string   `json:"image_name,omitempty"`   // container image name
	PodName     string   `json:"pod_name,omitempty"`     // Kubernetes pod name
	Namespace   string   `json:"namespace,omitempty"`    // Kubernetes namespace
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
	DNSQuery       string           `json:"dns_query,omitempty"`       // reverse PTR hostname (legacy)
	ResolvedDomain string           `json:"resolved_domain,omitempty"` // forward domain from DNS snooper
	ResolvedIPs    []string         `json:"resolved_ips,omitempty"`    // all IPs for that domain
	GeoCountry     string           `json:"geo_country,omitempty"`
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

// AuthEvent represents a login, authentication failure, or sudo execution.
type AuthEvent struct {
	BaseEvent
	Username  string `json:"username"`
	SourceIP  string `json:"source_ip,omitempty"` // remote IP for SSH logins
	Service   string `json:"service"`             // sshd, login, sudo, su, gdm
	TTY       string `json:"tty,omitempty"`
	Method    string `json:"method,omitempty"`     // password, publickey, keyboard-interactive
	TargetUser string `json:"target_user,omitempty"` // for sudo: the target user
	Command   string `json:"command,omitempty"`     // for sudo: the command run
	RawLog    string `json:"raw_log,omitempty"`     // original log line
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

// ─── Package Inventory Events ─────────────────────────────────────────────

// PackageInfo describes a single installed package.
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// PkgInventoryEvent carries a full package inventory snapshot from the endpoint.
type PkgInventoryEvent struct {
	BaseEvent
	Packages  []PackageInfo `json:"packages"`
	OS        string        `json:"os"`
	OSVersion string        `json:"os_version"`
}

// ─── Browser Request Events ──────────────────────────────────────────────

// BrowserRequestEvent is emitted by the browser monitor when the OEDR
// browser extension reports a completed web request.
type BrowserRequestEvent struct {
	BaseEvent
	URL           string   `json:"url"`
	Domain        string   `json:"domain"`
	Path          string   `json:"path"`
	Method        string   `json:"method"`
	StatusCode    int      `json:"status_code"`     // 0 = connection error
	ContentType   string   `json:"content_type,omitempty"`
	Referrer      string   `json:"referrer,omitempty"`
	TabURL        string   `json:"tab_url,omitempty"`       // URL of the tab that made the request
	ResourceType  string   `json:"resource_type,omitempty"` // main_frame, sub_frame, xmlhttprequest
	ServerIP      string   `json:"server_ip,omitempty"`
	FromCache     bool     `json:"from_cache"`
	Error         string   `json:"error,omitempty"`
	IsFormSubmit  bool     `json:"is_form_submit"`          // POST to main_frame = credential submission
	RedirectChain []string `json:"redirect_chain,omitempty"`
	BrowserName   string   `json:"browser_name,omitempty"`
}

// ─── Kernel Module Events ─────────────────────────────────────────────────

// KernelModuleEvent is emitted when a kernel module is loaded or unloaded.
type KernelModuleEvent struct {
	BaseEvent
	ModuleName string `json:"module_name"`
	Size       int64  `json:"size"`                    // module size in bytes (0 on unload)
	LoadedBy   string `json:"loaded_by,omitempty"`     // process that loaded it if known
	Tainted    bool   `json:"tainted"`                 // kernel tainted flag
	Signed     bool   `json:"signed"`                  // module has valid signature
	FilePath   string `json:"file_path,omitempty"`     // path to .ko file if found
}

// USBDeviceEvent is emitted when a USB device is connected or disconnected.
type USBDeviceEvent struct {
	BaseEvent
	DeviceName string `json:"device_name"`              // e.g. "sdb", "sdb1"
	VendorID   string `json:"vendor_id"`                // USB vendor ID (hex)
	ProductID  string `json:"product_id"`               // USB product ID (hex)
	Vendor     string `json:"vendor"`                   // human-readable vendor name
	Product    string `json:"product"`                  // human-readable product name
	Serial     string `json:"serial,omitempty"`
	BusNum     string `json:"bus_num"`
	DevNum     string `json:"dev_num"`
	DevType    string `json:"dev_type"`                 // "mass_storage", "hid", "audio", etc.
	MountPoint string `json:"mount_point,omitempty"`    // if auto-mounted
}

// ─── Named Pipe Events ───────────────────────────────────────────────────

// PipeEvent is emitted when a named pipe (FIFO) is created in a watched directory.
type PipeEvent struct {
	BaseEvent
	PipePath    string `json:"pipe_path"`
	CreatorPID  uint32 `json:"creator_pid,omitempty"`
	CreatorComm string `json:"creator_comm,omitempty"`
	Permissions string `json:"permissions"`
	Location    string `json:"location"` // "tmp", "dev_shm", "run", "other"
}

// ─── Network Share Events ────────────────────────────────────────────────

// ShareMountEvent is emitted when a network filesystem (NFS/CIFS/SMB) is mounted or unmounted.
type ShareMountEvent struct {
	BaseEvent
	Source     string `json:"source"`      // e.g. "//192.168.1.10/share"
	MountPoint string `json:"mount_point"` // e.g. "/mnt/share"
	FSType     string `json:"fs_type"`     // "cifs", "nfs", "nfs4"
	Options    string `json:"options"`     // mount options
	RemoteHost string `json:"remote_host"` // extracted IP/hostname
}

// ─── Memory Injection Events ──────────────────────────────────────────────

// MemoryInjectEvent is emitted when suspicious anonymous executable memory
// regions are detected in a process (potential shellcode or code injection).
type MemoryInjectEvent struct {
	BaseEvent
	TargetPID   uint32 `json:"target_pid"`
	TargetComm  string `json:"target_comm"`
	Address     string `json:"address"`     // hex address range
	Size        int64  `json:"size"`        // bytes
	Permissions string `json:"permissions"` // e.g. "rwxp"
	Description string `json:"description"` // what was detected
	Technique   string `json:"technique"`   // "anonymous_exec", "process_vm_write", "mprotect_exec", "memfd_exec"
}

// ─── Cron Modify Events ──────────────────────────────────────────────────

// CronModifyEvent is emitted when a crontab file or systemd timer is
// created, modified, or deleted.
type CronModifyEvent struct {
	BaseEvent
	FilePath   string   `json:"file_path"`
	Action     string   `json:"action"`                // "created", "modified", "deleted"
	CronUser   string   `json:"cron_user"`             // user the cron runs as
	Schedule   string   `json:"schedule"`              // e.g. "*/5 * * * *"
	Command    string   `json:"command"`               // the command to execute
	IsTimer    bool     `json:"is_timer"`              // systemd timer vs cron
	Suspicious bool     `json:"suspicious"`            // contains wget/curl/base64/encoded
	CronTags   []string `json:"cron_tags,omitempty"`   // "downloads", "encoded", "reverse-shell"
}
