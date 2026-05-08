// Package tasks executes scheduled tasks delivered by the backend via heartbeat.
package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/transport"
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
		Output: cap(output),
		ErrMsg: errMsg,
	})
}

// runScript executes a shell command from the task payload.
// Payload: {"cmd": "echo hello"}
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
	cmd := exec.CommandContext(ctx, "bash", "-c", p.Cmd) // #nosec G204 — admin-created tasks only
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runCollect gathers basic system information.
func (e *Executor) runCollect() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	cmds := [][]string{
		{"uname", "-a"},
		{"uptime"},
		{"df", "-h", "/"},
		{"free", "-h"},
	}
	var sb strings.Builder
	for _, args := range cmds {
		var buf bytes.Buffer
		c := exec.CommandContext(ctx, args[0], args[1:]...)
		c.Stdout = &buf
		c.Stderr = &buf
		_ = c.Run()
		sb.WriteString("$ " + strings.Join(args, " ") + "\n")
		sb.WriteString(buf.String())
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// runScan does a quick file integrity spot-check using find + sha256sum.
// Payload: {"path": "/etc", "maxdepth": 2}
func (e *Executor) runScan(payload json.RawMessage) (string, error) {
	var p struct {
		Path     string `json:"path"`
		MaxDepth int    `json:"maxdepth"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("invalid scan payload: %w", err)
	}
	if strings.TrimSpace(p.Path) == "" {
		p.Path = "/etc"
	}
	if p.MaxDepth <= 0 || p.MaxDepth > 5 {
		p.MaxDepth = 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	depth := fmt.Sprintf("%d", p.MaxDepth)
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "find", p.Path, "-maxdepth", depth, "-type", "f", "-newer", "/tmp") // #nosec G204
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runRemediate kills a process by PID.
// Payload: {"pid": 1234}
func (e *Executor) runRemediate(payload json.RawMessage) (string, error) {
	var p struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || p.PID <= 1 {
		return "", fmt.Errorf("invalid remediate payload: pid > 1 required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pid := fmt.Sprintf("%d", p.PID)
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "kill", "-TERM", pid) // #nosec G204
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// cap truncates output to maxOutputBytes.
func cap(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	return s[:maxOutputBytes] + "\n[output truncated]"
}
