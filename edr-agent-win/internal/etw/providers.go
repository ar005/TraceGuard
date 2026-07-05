//go:build windows

package etw

import "golang.org/x/sys/windows"

// Provider GUIDs as windows.GUID structs — used by Session.EnableProvider.
// The string constants in session.go (ProviderKernelProcess etc.) are kept for
// backward compatibility with existing imports.
var (
	// Microsoft-Windows-Kernel-Process: events 1=Start, 2=Stop, 5=Rundown
	GUIDKernelProcess = windows.GUID{
		Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b,
		Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
	}
	// Microsoft-Windows-Kernel-Network: TCP/UDP/IPv4/IPv6 connection events
	GUIDKernelNetwork = windows.GUID{
		Data1: 0x7dd42a49, Data2: 0x5329, Data3: 0x4832,
		Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88},
	}
	// Microsoft-Windows-Kernel-File: file create/write/delete/rename
	GUIDKernelFile = windows.GUID{
		Data1: 0xedd08927, Data2: 0x9cc4, Data3: 0x4e65,
		Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89},
	}
	// Microsoft-Windows-Kernel-Registry: registry set/delete/create/rename
	GUIDKernelRegistry = windows.GUID{
		Data1: 0x70eb4f03, Data2: 0xc1de, Data3: 0x4f73,
		Data4: [8]byte{0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd},
	}
	// Microsoft-Windows-DNS-Client: event 3008=QueryPerformed (includes PID)
	GUIDDNSClient = windows.GUID{
		Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9,
		Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d},
	}
	// Microsoft-Windows-PowerShell: command execution telemetry
	GUIDPowerShell = windows.GUID{
		Data1: 0xa0c1853b, Data2: 0x5c40, Data3: 0x4b15,
		Data4: [8]byte{0x87, 0x66, 0x3c, 0xf1, 0xc5, 0x8f, 0x98, 0x5a},
	}
)

// Kernel-Process event IDs.
const (
	EventProcessStart   uint16 = 1
	EventProcessStop    uint16 = 2
	EventProcessRundown uint16 = 5
)

// Kernel-Network event IDs (TCP IPv4/IPv6, UDP IPv4/IPv6).
const (
	EventTcpConnect      uint16 = 10
	EventTcpDisconnect   uint16 = 11
	EventTcpAccept       uint16 = 14
	EventTcpResetClient  uint16 = 15
	EventUdpSend         uint16 = 26
	EventUdpReceive      uint16 = 27
	EventTcpv6Connect    uint16 = 58
	EventTcpv6Disconnect uint16 = 61
	EventUdpv6Send       uint16 = 67
	EventUdpv6Receive    uint16 = 68
)

// Kernel-File event IDs.
const (
	EventFileCreate  uint16 = 12
	EventFileDelete  uint16 = 13
	EventFileWrite   uint16 = 14
	EventFileRename  uint16 = 10
	EventFileSetInfo uint16 = 16
)

// Kernel-Registry event IDs.
const (
	EventRegSetValue    uint16 = 1
	EventRegDeleteValue uint16 = 2
	EventRegCreateKey   uint16 = 3
	EventRegDeleteKey   uint16 = 5
)

// DNS-Client event IDs.
const (
	EventDNSQuery uint16 = 3008
)

// ETW trace level constants.
const (
	TraceLevelCritical    uint8 = 1
	TraceLevelError       uint8 = 2
	TraceLevelWarning     uint8 = 3
	TraceLevelInformation uint8 = 4
	TraceLevelVerbose     uint8 = 5
)
