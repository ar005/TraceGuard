# TraceGuard Agent for Windows — Implementation Plan

## Overview

Build a Windows EDR agent with the same 15 monitoring capabilities as the Linux agent. Windows has fundamentally different APIs for system monitoring — no eBPF, no /proc, no /sys. Every monitor needs a Windows-native reimplementation.

## Difficulty: High

This is a multi-month effort. Windows monitoring requires ETW (Event Tracing for Windows), WMI, native Win32 APIs, Windows Filtering Platform (WFP), and deep understanding of Windows internals.

---

## Architecture

```
Windows Endpoint
├── edr-agent-windows.exe (Go binary)
│   ├── ETW Consumer (process, network, file, DNS, registry)
│   ├── WMI Watchers (USB, services, scheduled tasks)
│   ├── Windows API monitors (memory, modules, shares, auth)
│   ├── Browser extension receiver (same HTTP localhost:9999)
│   └── gRPC Transport → Backend (same backend, no changes)
└── Optional: kernel driver for deep monitoring (future)
```

### Key Technology Mapping

| Linux | Windows Equivalent | Complexity |
|-------|-------------------|------------|
| eBPF tracepoints | ETW (Event Tracing for Windows) | High |
| /proc filesystem | Win32 API + WMI | Medium |
| /sys/bus/usb | WMI + SetupAPI | Medium |
| AF_PACKET raw socket | WFP (Windows Filtering Platform) or Npcap | High |
| iptables | WFP or Windows Firewall COM API | High |
| inotify / file hooks | NTFS change journal / ReadDirectoryChangesW | Medium |
| auth.log | Windows Event Log (Security) | Medium |
| /proc/modules | EnumDeviceDrivers / NtQuerySystemInformation | Medium |
| /proc/*/maps | VirtualQueryEx | Medium |

---

## Phase 1 — Core Agent Framework (1 week)

### Go on Windows

Go compiles natively for Windows. The core framework (config, event bus, transport, buffer) works with minimal changes:

| Component | Changes Needed |
|-----------|---------------|
| Event bus | None — pure Go |
| gRPC transport | None — Go gRPC works on Windows |
| Local buffer (SQLite) | None — go-sqlite3 works on Windows |
| Config loader (Viper) | Change default paths to `C:\ProgramData\TraceGuard\` |
| Logger | Change log path to `C:\ProgramData\TraceGuard\Logs\` |
| Browser monitor | None — HTTP server on localhost works |

### Windows-specific changes

```go
// config paths
const (
    DefaultConfigPath = `C:\ProgramData\TraceGuard\agent.yaml`
    DefaultIDFile     = `C:\ProgramData\TraceGuard\agent.id`
    DefaultBufferPath = `C:\ProgramData\TraceGuard\events.db`
    DefaultLogPath    = `C:\ProgramData\TraceGuard\Logs\agent.log`
    QuarantineDir     = `C:\ProgramData\TraceGuard\Quarantine`
)
```

### Build

```bash
GOOS=windows GOARCH=amd64 go build -o edr-agent.exe ./cmd/agent/
```

### Windows Service

Install as a Windows service using `golang.org/x/sys/windows/svc`:

```go
// cmd/agent/service_windows.go
package main

import (
    "golang.org/x/sys/windows/svc"
)

type TraceGuardService struct{}

func (s *TraceGuardService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
    // Start agent, handle stop/shutdown signals
}
```

Install:
```powershell
sc.exe create TraceGuardAgent binpath= "C:\Program Files\TraceGuard\edr-agent.exe --config C:\ProgramData\TraceGuard\agent.yaml" start= auto
sc.exe start TraceGuardAgent
```

---

## Phase 2 — ETW-Based Monitors (2-3 weeks)

ETW (Event Tracing for Windows) is Windows' primary telemetry system. One ETW consumer can replace multiple Linux monitors.

### Required Go ETW library

Use `github.com/Microsoft/go-winio` or `github.com/bi-zone/etw` for Go ETW consumption.

### Process Monitor via ETW

**ETW Provider**: `Microsoft-Windows-Kernel-Process` (GUID: `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)

**Events to capture**:
| ETW Event ID | Equivalent | Linux Event |
|-------------|-----------|-------------|
| ProcessStart (1) | Process creation | PROCESS_EXEC |
| ProcessStop (2) | Process exit | PROCESS_EXIT |
| ImageLoad (5) | DLL/module load | — (new) |

**Data available per event**:
- Process ID, Parent PID, Session ID
- Image file name, command line
- Token elevation type, integrity level
- Creating process ID
- User SID

```go
// monitor/process_windows/monitor.go
func (m *Monitor) Start(ctx context.Context) error {
    session, err := etw.NewSession("TraceGuardProcessMon")
    if err != nil { return err }

    session.Subscribe("Microsoft-Windows-Kernel-Process", func(e *etw.Event) {
        switch e.ID {
        case 1: // ProcessStart
            m.handleProcessStart(e)
        case 2: // ProcessStop
            m.handleProcessStop(e)
        }
    })

    go session.Run(ctx)
    return nil
}
```

### Network Monitor via ETW

**ETW Provider**: `Microsoft-Windows-Kernel-Network` (GUID: `{7DD42A49-5329-4832-8DFD-43D979153A88}`)

**Events**:
| ETW Event ID | Type | Linux Event |
|-------------|------|-------------|
| TcpIp/Connect (12) | TCP connect | NET_CONNECT |
| TcpIp/Accept (15) | TCP accept | NET_ACCEPT |
| TcpIp/Disconnect (14) | TCP close | NET_CLOSE |
| UdpIp/Send (10) | UDP send | NET_CONNECT |

**Data**: PID, src/dst IP, src/dst port, process name.

### File Monitor via ETW

**ETW Provider**: `Microsoft-Windows-Kernel-File` (GUID: `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`)

**Events**:
| ETW Event ID | Type | Linux Event |
|-------------|------|-------------|
| FileCreate (12) | File creation | FILE_CREATE |
| FileWrite (15) | File modification | FILE_WRITE |
| FileDelete (26) | File deletion | FILE_DELETE |
| FileRename (19) | File rename | FILE_RENAME |

**Data**: File path, PID, operation type, file size.

### DNS Monitor via ETW

**ETW Provider**: `Microsoft-Windows-DNS-Client` (GUID: `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`)

**Events**: DNS query name, query type, result IPs, PID.

This is **much easier** than the Linux raw socket DNS snooper — ETW gives you DNS with PID attribution natively.

### Registry Monitor via ETW

**ETW Provider**: `Microsoft-Windows-Kernel-Registry`

**Events**: Key create, key delete, value set, value delete — with full key path and PID.

This replaces the Linux "registry" monitor that watches `/etc` files.

---

## Phase 3 — Win32 API Monitors (1-2 weeks)

### Auth/Login Monitor

**Source**: Windows Security Event Log (Event IDs 4624, 4625, 4634, 4648)

```go
// Use golang.org/x/sys/windows to read Event Log
// or WMI: SELECT * FROM Win32_NTLogEvent WHERE Logfile='Security'

// Event ID mapping:
// 4624 → LOGIN_SUCCESS (with logon type: interactive, network, RDP, etc.)
// 4625 → LOGIN_FAILED
// 4648 → Explicit credential use (runas)
// 4672 → Special privileges assigned (admin login)
```

### USB Monitor

**Source**: WMI `Win32_USBControllerDevice` + SetupAPI

```go
// Poll WMI for USB devices:
// SELECT * FROM Win32_PnPEntity WHERE Service='USBSTOR'
//
// Or use RegisterDeviceNotification for real-time:
// DBT_DEVICEARRIVAL (USB connect)
// DBT_DEVICEREMOVECOMPLETE (USB disconnect)
```

**Data**: Device instance ID, vendor ID, product ID, serial number, drive letter.

### Kernel Module (Driver) Monitor

**Source**: `EnumDeviceDrivers()` + `GetDeviceDriverFileName()`

```go
// Poll loaded drivers periodically
// Compare with baseline to detect new driver loads
// Check driver signature status via WinVerifyTrust
```

### Memory Injection Monitor

**Source**: `VirtualQueryEx()` + `NtQueryVirtualMemory()`

```go
// For each process, enumerate memory regions:
// VirtualQueryEx(hProcess, ...)
// Look for MEM_PRIVATE + PAGE_EXECUTE_READWRITE (RWX) regions
// Alert on anonymous executable memory (shellcode indicator)

// Also monitor:
// CreateRemoteThread → remote thread injection
// WriteProcessMemory → process memory write
// NtMapViewOfSection → section mapping (process hollowing)
```

### Scheduled Task Monitor (Cron equivalent)

**Source**: Task Scheduler COM API or `schtasks.exe`

```go
// Poll: schtasks /query /fo CSV /v
// Or use COM: ITaskService → ITaskFolder → GetTasks
// Detect new/modified scheduled tasks
// Flag suspicious: encoded commands, download URLs, persistence locations
```

### Named Pipe Monitor

**Source**: `\\.\pipe\` enumeration

```go
// List pipes: FindFirstFileW(L"\\\\.\\pipe\\*", ...)
// Detect new pipes: compare with baseline
// Flag known C2 pipes: cobaltstrike default pipes, PsExec pipes
```

### Network Share Monitor

**Source**: `NetShareEnum()` or WMI `Win32_Share`

```go
// Detect new shares created
// Monitor access to admin shares (C$, ADMIN$, IPC$)
// Detect lateral movement via share access
```

---

## Phase 4 — TLS SNI + Network Blocking (1 week)

### TLS SNI on Windows

**Option A**: Use Npcap (WinPcap successor) for packet capture
```go
// github.com/google/gopacket + github.com/google/gopacket/pcap
// Capture on port 443, parse TLS ClientHello same as Linux
// Requires Npcap installed
```

**Option B**: Use WFP (Windows Filtering Platform) callout driver
```
// Kernel driver that inspects TLS traffic
// Much more complex but doesn't require Npcap
// Future consideration
```

**Recommended**: Option A (Npcap) for v1, Option B for v2.

### IP Blocking on Windows

Replace iptables with Windows Firewall:

```go
// Use netsh or Windows Firewall COM API:
// netsh advfirewall firewall add rule name="TraceGuard_BLOCK_1.2.3.4" dir=in action=block remoteip=1.2.3.4
// netsh advfirewall firewall add rule name="TraceGuard_BLOCK_1.2.3.4" dir=out action=block remoteip=1.2.3.4

// Or use WFP API for programmatic firewall control (more robust)
```

### File Quarantine on Windows

```go
// Same concept: copy to quarantine dir, remove original
// Additional: use SetFileAttributes to mark as SYSTEM+HIDDEN
// Additional: set NTFS ACL to deny all access except TraceGuard service
// Quarantine dir: C:\ProgramData\TraceGuard\Quarantine\
```

---

## Phase 5 — Windows-Specific Detections (1 week)

### New detection rules for Windows

| Rule | What it detects | ETW/API |
|------|----------------|---------|
| LSASS memory access | Credential dumping (Mimikatz) | Process accessing lsass.exe memory |
| Service creation | Persistence via new service | Service Control Manager events |
| WMI persistence | WMI event subscription backdoor | WMI ETW provider |
| PowerShell execution | Encoded/obfuscated commands | PowerShell ETW provider |
| RDP lateral movement | Remote Desktop connections | Security Event Log 4624 type 10 |
| DLL side-loading | Malicious DLL in trusted app dir | Image load with path mismatch |
| UAC bypass | Privilege escalation | Token elevation type changes |
| AMSI bypass | Security tool evasion | AMSI ETW provider |
| COM hijacking | Persistence via COM registration | Registry monitor |
| Sysmon equivalent | Full process tree with hashes | Kernel-Process ETW |

### MITRE ATT&CK Windows-specific techniques

| Technique | ID | Monitor |
|-----------|-----|---------|
| OS Credential Dumping | T1003 | LSASS access detection |
| Windows Service | T1543.003 | Service creation monitor |
| PowerShell | T1059.001 | PowerShell ETW |
| Remote Desktop Protocol | T1021.001 | Auth monitor (type 10) |
| DLL Side-Loading | T1574.002 | Image load monitor |
| UAC Bypass | T1548.002 | Token elevation monitor |
| WMI | T1047 | WMI ETW |
| Scheduled Task | T1053.005 | Task Scheduler monitor |

---

## Phase 6 — Installer & Deployment (3-5 days)

### MSI Installer

Build an MSI installer using WiX Toolset:

```xml
<!-- TraceGuard Agent MSI -->
<Product Name="TraceGuard Agent" Version="1.0.0" Manufacturer="TraceGuard">
  <Package InstallerVersion="500" />
  <Directory Id="TARGETDIR" Name="SourceDir">
    <Directory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="TraceGuard">
        <Component>
          <File Source="edr-agent.exe" />
          <ServiceInstall Name="TraceGuardAgent"
                         DisplayName="TraceGuard Endpoint Agent"
                         Start="auto" Type="ownProcess" />
          <ServiceControl Id="StartService" Name="TraceGuardAgent"
                         Start="install" Stop="both" Remove="uninstall" />
        </Component>
      </Directory>
    </Directory>
  </Directory>
</Product>
```

### Group Policy deployment

```
# Deploy via GPO:
# Computer Configuration → Software Settings → Software Installation
# Add the MSI package for domain-wide deployment
```

### Configuration via registry

```
HKLM\SOFTWARE\TraceGuard\Agent\
  BackendURL = "backend.company.com:50051"
  TLSInsecure = 0
  Tags = "windows,domain-controller"
```

---

## Monitor Capability Matrix: Linux vs Windows

| Monitor | Linux Method | Windows Method | Difficulty |
|---------|-------------|---------------|------------|
| **Process exec/exit** | eBPF tracepoint | ETW Kernel-Process | Medium |
| **Network connections** | eBPF kprobe | ETW Kernel-Network | Medium |
| **File integrity** | eBPF kprobe | ETW Kernel-File / USN Journal | Medium |
| **DNS queries** | Raw socket | ETW DNS-Client | Easy (ETW is easier) |
| **Registry/config** | inotify on /etc | ETW Kernel-Registry | Easy |
| **Auth/login** | auth.log tail | Security Event Log | Medium |
| **Command history** | Shell history files | PowerShell ETW + cmd ETW | Medium |
| **USB devices** | /sys polling | WMI + SetupAPI | Medium |
| **Kernel modules** | /proc/modules | EnumDeviceDrivers | Easy |
| **Memory injection** | /proc/*/maps | VirtualQueryEx + ETW | Hard |
| **Scheduled tasks** | Cron file parsing | Task Scheduler COM | Medium |
| **Named pipes** | Filesystem scan | \\.\pipe\ enumeration | Easy |
| **Network shares** | /proc/mounts | NetShareEnum / WMI | Easy |
| **TLS SNI** | AF_PACKET socket | Npcap / WFP | Medium-Hard |
| **Browser URLs** | Extension receiver | Same (HTTP localhost) | None |

---

## Dependencies

| Library | Purpose | License |
|---------|---------|---------|
| `github.com/bi-zone/etw` | ETW consumption in Go | MIT |
| `golang.org/x/sys/windows` | Windows API bindings | BSD |
| `golang.org/x/sys/windows/svc` | Windows service | BSD |
| `github.com/go-ole/go-ole` | COM/WMI interop | MIT |
| `github.com/google/gopacket` | Packet capture (for SNI) | BSD |
| Npcap runtime | Packet capture driver | Free for personal use |

---

## Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | 1 week | Core framework, config, service, gRPC transport |
| Phase 2 | 2-3 weeks | ETW monitors (process, network, file, DNS, registry) |
| Phase 3 | 1-2 weeks | Win32 API monitors (auth, USB, drivers, memory, tasks, pipes, shares) |
| Phase 4 | 1 week | TLS SNI via Npcap, Windows Firewall IP blocking, file quarantine |
| Phase 5 | 1 week | Windows-specific detection rules (LSASS, PowerShell, UAC, RDP) |
| Phase 6 | 3-5 days | MSI installer, Group Policy, service management |
| **Total** | **7-9 weeks** | **Full Windows agent with 15+ monitors** |

---

## Testing Checklist

- [ ] Agent compiles for windows/amd64
- [ ] Installs as Windows service
- [ ] Starts on boot
- [ ] ETW process monitoring captures cmd.exe, powershell.exe
- [ ] ETW network monitoring captures TCP connections
- [ ] ETW file monitoring captures file writes
- [ ] DNS queries captured via ETW
- [ ] Registry changes detected
- [ ] Windows Event Log auth monitoring (4624/4625)
- [ ] USB device detection via WMI
- [ ] Driver enumeration works
- [ ] Memory injection detection via VirtualQueryEx
- [ ] Scheduled task monitoring
- [ ] Named pipe detection
- [ ] Network share monitoring
- [ ] TLS SNI capture via Npcap
- [ ] IP blocking via Windows Firewall
- [ ] File quarantine with NTFS ACLs
- [ ] Browser extension receiver works
- [ ] Events stream to backend via gRPC
- [ ] Events visible in UI dashboard
- [ ] All Windows-specific detection rules fire
- [ ] MSI installer works
- [ ] GPO deployment works
- [ ] Memory usage < 150MB idle
- [ ] CPU usage < 5% idle
- [ ] Uninstall cleanly removes service and files
