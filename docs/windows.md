# TraceGuard Windows Agent Documentation

## Overview

The Windows agent (`edr-agent-win`) is a Go binary that monitors Windows 11 endpoints using ETW (Event Tracing for Windows), Win32 APIs, and WMI. It sends telemetry to the same backend as the Linux agent via gRPC, using the same JSON-codec transport. All backend features — detection, alerting, incidents, live response, scheduled tasks — work identically across Linux and Windows agents.

The agent is a separate Go module (`github.com/youredr/edr-agent-win`) with its own `go.mod`. It uses `modernc.org/sqlite` (pure Go, no CGO) for the local event buffer, so it cross-compiles from Linux without requiring a Windows toolchain.

## Prerequisites

| Requirement | Notes |
|---|---|
| Go 1.25+ | For building |
| Windows 11 / Windows Server 2019+ | Target runtime |
| Admin / SYSTEM privileges | Required for ETW, WMI, and network containment |

## Build

### Cross-compile from Linux

```bash
cd edr-agent-win
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o edr-agent.exe ./cmd/agent/
```

CGO is not required because `modernc.org/sqlite` is a pure-Go SQLite implementation.

### Build on Windows

```cmd
go build -o edr-agent.exe ./cmd/agent/
```

### Install as Windows Service

```powershell
sc.exe create TraceGuardAgent `
  binpath= "C:\Program Files\TraceGuard\edr-agent.exe --config C:\ProgramData\TraceGuard\agent.yaml" `
  start= auto
sc.exe start TraceGuardAgent
```

## Configuration

Default config paths:

```
C:\ProgramData\TraceGuard\agent.yaml
C:\ProgramData\TraceGuard\agent.id
C:\ProgramData\TraceGuard\events.db
C:\ProgramData\TraceGuard\Logs\agent.log
C:\ProgramData\TraceGuard\Quarantine\
```

Configuration keys are the same as the Linux agent (see `docs/agent.md`). All `EDR_` environment variable overrides work on Windows.

## Monitors (18)

| Monitor | Implementation | Events Emitted |
|---------|---------------|----------------|
| **Process** | ETW `Microsoft-Windows-Kernel-Process` | PROCESS_EXEC, PROCESS_EXIT |
| **Network** | ETW `Microsoft-Windows-Kernel-Network` | NET_CONNECT, NET_ACCEPT, NET_CLOSE |
| **File** | ETW `Microsoft-Windows-Kernel-File` | FILE_CREATE, FILE_WRITE, FILE_DELETE, FILE_RENAME |
| **File Integrity (FIM)** | `ReadDirectoryChangesW` | FILE_WRITE (on watched paths) |
| **DNS** | ETW `Microsoft-Windows-DNS-Client` | NET_DNS (with PID attribution) |
| **Auth** | Windows Security Event Log (IDs 4624/4625/4634/4648) | LOGIN_SUCCESS, LOGIN_FAILED |
| **Command** | PowerShell ETW + cmd ETW | EventCmdExec |
| **Registry** | ETW `Microsoft-Windows-Kernel-Registry` | EventRegistrySet, EventRegistryDelete |
| **Vulnerability** | winget / WMI `Win32_Product` | PKG_INVENTORY |
| **Browser** | HTTP receiver on localhost:9999 | BROWSER_REQUEST |
| **Driver** | `EnumDeviceDrivers()` polling | KERNEL_MODULE_LOAD, KERNEL_MODULE_UNLOAD |
| **USB** | WMI `Win32_USBControllerDevice` + SetupAPI | USB_CONNECT, USB_DISCONNECT |
| **Memory Injection** | `VirtualQueryEx()` + `NtQueryVirtualMemory()` | MEMORY_INJECT |
| **Scheduled Task** | Task Scheduler COM API | (task monitoring events) |
| **Named Pipe** | `\\.\pipe\` enumeration | PIPE_CREATE |
| **Network Share** | `NetShareEnum()` / WMI `Win32_Share` | SHARE_MOUNT |
| **Windows Event Log** | WMI/ETW | WinEventLogEvent |
| **Agent lifecycle** | internal | AGENT_START, AGENT_STOP, AGENT_HEARTBEAT |

### Windows-specific event types

| Event Type | Description |
|---|---|
| `EventCmdExec` | A command was executed via PowerShell or cmd.exe. Includes command text, PID, user. |
| `EventRegistrySet` | A registry key value was set. Includes full key path, value name, data, PID. |
| `EventRegistryDelete` | A registry key or value was deleted. Includes full key path, PID. |
| `WinEventLogEvent` | A Windows Security Event Log entry. Includes event ID, channel, keywords, and event-specific fields. Common IDs: 4624 (logon success), 4625 (logon failure), 4648 (explicit credential logon), 4672 (special privileges). |

## Scheduled Tasks

The Windows agent uses the same heartbeat-based task delivery mechanism as the Linux agent. Tasks are received in `HeartbeatResponse.pending_tasks[]` and results are reported in the next `HeartbeatRequest.task_results[]`.

### Windows task execution

| Task Type | Implementation | Payload |
|-----------|---------------|---------|
| `script` | `powershell.exe -NoProfile -NonInteractive -Command <cmd>` | `{"cmd": "Get-Process"}` |
| `collect` | PowerShell CIM queries (Win32_OperatingSystem, disk/memory) | (none) |
| `scan` | `Get-ChildItem -Recurse` filtered by `LastWriteTime` | `{"path": "C:\\Windows\\System32", "days": 1}` |
| `remediate` | `taskkill.exe /F /T /PID <pid>` | `{"pid": 1234}` |

**Safety constraint for `remediate`:** PID must be > 4 (blocks PID 0–4, which includes System and Critical System processes on Windows).

Output is capped at 64 KB combined stdout+stderr. Script timeout: 5 minutes. Collect/scan timeout: 30 seconds.

### Example: run a script task

```json
POST /api/v1/agents/<agent_id>/tasks
{
  "name": "Check running services",
  "type": "script",
  "schedule": "",
  "payload": {"cmd": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | ConvertTo-Json"}
}
```

## Live Response

The Windows agent connects the same `LiveResponse` gRPC bidi stream as the Linux agent. The same command allowlist applies. Available commands:

`ps`, `ls`, `cat`, `netstat`, `who`, `uname`, `uptime`, `df`, `id`, `exec`, `find`, `sha256sum`, `kill`, `isolate`, `release`

**Network containment on Windows** uses Windows Firewall (via `netsh advfirewall`) instead of iptables. The semantics are identical: `isolate` blocks all traffic except the backend gRPC channel; `release` removes the firewall rules.

## Transport

Identical to the Linux agent:
- JSON-encoded gRPC transport
- Client-streaming `StreamEvents` RPC
- Unary `Heartbeat` RPC (30s interval) — carries `task_results[]` and receives `pending_tasks[]`
- Bidirectional `LiveResponse` stream
- SQLite local buffer (`modernc.org/sqlite`, pure Go) for offline resilience
- mTLS support via `agent.tls.*` config keys

## Detection rules

The same detection rules run on Windows as on Linux — they match on event payload fields, so rules that target `event_type = PROCESS_EXEC` fire on Windows too. Additional Windows-specific rules to consider:

| Rule concept | Event Types | MITRE |
|---|---|---|
| LSASS memory access | MEMORY_INJECT + PROCESS_EXEC | T1003.001 |
| PowerShell encoded command | EventCmdExec | T1059.001 |
| Suspicious registry persistence keys | EventRegistrySet | T1547.001 |
| Scheduled task creation | (task monitor event) | T1053.005 |
| UAC bypass (token elevation type) | PROCESS_EXEC | T1548.002 |
| RDP lateral movement | LOGIN_SUCCESS (type 10) | T1021.001 |

## Dependencies

| Library | Purpose |
|---|---|
| `modernc.org/sqlite` | Pure-Go SQLite (no CGO required) |
| `golang.org/x/sys/windows` | Windows API bindings |
| `google.golang.org/grpc` | gRPC transport |
| `github.com/rs/zerolog` | Structured logging |
| `github.com/spf13/viper` | Configuration loading |

## Testing

```bash
cd edr-agent-win
go test ./... -v -race
```

Cross-compile check:
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```
