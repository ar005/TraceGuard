// internal/etw/session.go
// Shared ETW session wrapper for Windows monitors.
// Uses github.com/bi-zone/etw for consuming Event Tracing for Windows events.
//
// ETW is the Windows equivalent of eBPF — it provides kernel-level telemetry
// for process, network, file, DNS, and registry activity.

package etw

// ProviderGUID constants for ETW providers used by TraceGuard monitors.
const (
	// Microsoft-Windows-Kernel-Process — process creation, exit, image load
	ProviderKernelProcess = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

	// Microsoft-Windows-Kernel-Network — TCP/UDP connections
	ProviderKernelNetwork = "{7DD42A49-5329-4832-8DFD-43D979153A88}"

	// Microsoft-Windows-Kernel-File — file I/O operations
	ProviderKernelFile = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"

	// Microsoft-Windows-Kernel-Registry — registry key/value changes
	ProviderKernelRegistry = "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"

	// Microsoft-Windows-DNS-Client — DNS query resolution
	ProviderDNSClient = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"

	// Microsoft-Windows-PowerShell — PowerShell command execution
	ProviderPowerShell = "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"
)

// Event IDs for each ETW provider.
const (
	// Kernel-Process events
	EventIDProcessStart = 1
	EventIDProcessStop  = 2
	EventIDImageLoad    = 5

	// Kernel-Network events
	EventIDTcpConnect    = 12
	EventIDTcpDisconnect = 14
	EventIDTcpAccept     = 15
	EventIDUdpSend       = 10

	// Kernel-File events
	EventIDFileCreate = 12
	EventIDFileWrite  = 15
	EventIDFileDelete = 26
	EventIDFileRename = 19

	// DNS-Client events
	EventIDDNSQuery    = 3006
	EventIDDNSResponse = 3008

	// Security Event Log IDs (not ETW, but referenced here for convenience)
	SecurityLogonSuccess    = 4624
	SecurityLogonFailed     = 4625
	SecurityLogoff          = 4634
	SecurityExplicitLogon   = 4648
	SecuritySpecialPriv     = 4672
)
