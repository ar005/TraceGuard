// Package tasks executes scheduled tasks delivered by the backend via heartbeat.
package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"os/exec"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/transport"
)

const (
	maxOutputBytes = 64 * 1024 // 64 KB cap on combined stdout+stderr
	scriptTimeout  = 5 * time.Minute
	collectTimeout = 30 * time.Second
)

// Reporter is satisfied by *transport.GRPCTransport.
type Reporter interface {
	ReportTaskResult(r transport.TaskResult)
}

// Executor dispatches incoming task instructions and reports results.
type Executor struct {
	reporter Reporter
	log      zerolog.Logger
}

// New creates an Executor.
func New(r Reporter, log zerolog.Logger) *Executor {
	return &Executor{reporter: r, log: log.With().Str("component", "task-executor").Logger()}
}

// Handle is called by the transport layer for each task received from the backend.
// It runs in its own goroutine.
func (e *Executor) Handle(task transport.TaskInstruction) {
	e.log.Info().Str("id", task.ID).Str("type", task.Type).Str("name", task.Name).Msg("executing task")

	var output, errMsg string
	var err error

	switch task.Type {
	case "script":
		output, err = e.runScript(task.Payload)
	case "collect":
		output, err = e.runCollect()
	case "scan":
		output, err = e.runScan(task.Payload)
	case "remediate":
		output, err = e.runRemediate(task.Payload)
	default:
		err = fmt.Errorf("unknown task type %q", task.Type)
	}

	status := "success"
	if err != nil {
		status = "failed"
		errMsg = err.Error()
		e.log.Warn().Str("id", task.ID).Err(err).Msg("task failed")
	} else {
		e.log.Info().Str("id", task.ID).Msg("task completed")
	}

	e.reporter.ReportTaskResult(transport.TaskResult{
		TaskID: task.ID,
		Status: status,
		Output: capOutput(output),
		ErrMsg: errMsg,
	})
}

// runScript executes a PowerShell command from the task payload.
// Payload: {"cmd": "Get-Process | Select-Object -First 5"}
func (e *Executor) runScript(payload json.RawMessage) (string, error) {
	var p struct {
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || strings.TrimSpace(p.Cmd) == "" {
		return "", fmt.Errorf("invalid script payload: cmd is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()

	var buf bytes.Buffer
	// -NoProfile -NonInteractive keep startup fast and output clean.
	cmd := exec.CommandContext(ctx, "powershell.exe", // #nosec G204 — admin-created tasks only
		"-NoProfile", "-NonInteractive", "-Command", p.Cmd)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runCollect gathers basic Windows system information via PowerShell.
func (e *Executor) runCollect() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	script := `
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "=== OS ==="
(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List | Out-String).Trim()
Write-Output ""
Write-Output "=== Uptime ==="
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
"Last boot: $boot  Uptime: $([math]::Round(((Get-Date) - $boot).TotalHours,1)) hours"
Write-Output ""
Write-Output "=== Disk ==="
Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{n='Used(GB)';e={[math]::Round($_.Used/1GB,1)}},@{n='Free(GB)';e={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize | Out-String
Write-Output ""
Write-Output "=== Memory ==="
$os = Get-CimInstance Win32_OperatingSystem
"Total: $([math]::Round($os.TotalVisibleMemorySize/1MB,1)) GB  Free: $([math]::Round($os.FreePhysicalMemory/1MB,1)) GB"
`
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runScan lists recently modified files under a given path.
// Payload: {"path": "C:\\Windows\\System32", "days": 1}
func (e *Executor) runScan(payload json.RawMessage) (string, error) {
	var p struct {
		Path string `json:"path"`
		Days int    `json:"days"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("invalid scan payload: %w", err)
	}
	if strings.TrimSpace(p.Path) == "" {
		p.Path = `C:\Windows\System32`
	}
	if p.Days <= 0 || p.Days > 30 {
		p.Days = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	script := fmt.Sprintf(
		`Get-ChildItem -Path '%s' -Recurse -File -ErrorAction SilentlyContinue |`+
			` Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-%d) } |`+
			` Select-Object FullName,LastWriteTime,@{n='Size(KB)';e={[math]::Round($_.Length/1KB,1)}} |`+
			` Sort-Object LastWriteTime -Descending | Select-Object -First 50 |`+
			` Format-Table -AutoSize | Out-String`,
		p.Path, p.Days,
	)

	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runRemediate terminates a process by PID using taskkill.
// Payload: {"pid": 1234}
func (e *Executor) runRemediate(payload json.RawMessage) (string, error) {
	var p struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || p.PID <= 4 {
		// PID 4 is System on Windows; block 0–4 to avoid system process kills.
		return "", fmt.Errorf("invalid remediate payload: pid > 4 required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pid := fmt.Sprintf("%d", p.PID)
	var buf bytes.Buffer
	// /F = force, /T = include child processes
	cmd := exec.CommandContext(ctx, "taskkill.exe", "/F", "/T", "/PID", pid) // #nosec G204
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// capOutput truncates output to maxOutputBytes.
func capOutput(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	return s[:maxOutputBytes] + "\n[output truncated]"
}
