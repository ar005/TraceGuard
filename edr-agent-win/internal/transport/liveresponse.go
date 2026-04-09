// internal/transport/liveresponse.go
// Agent-side live response — Windows command equivalents.

package transport

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"google.golang.org/grpc"
)

const methodLiveResponse = "/edr.v1.EventService/LiveResponse"

type liveCommand struct {
	CommandID string   `json:"command_id"`
	Action    string   `json:"action"`
	Args      []string `json:"args"`
	Timeout   int      `json:"timeout"`
}

type liveResult struct {
	CommandID string `json:"command_id"`
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Error     string `json:"error,omitempty"`
}

var allowedActions = map[string]bool{
	"exec": true, "ps": true, "ls": true, "cat": true,
	"kill": true, "netstat": true, "df": true, "who": true,
	"id": true, "uname": true, "uptime": true, "stat": true,
	"find": true, "md5sum": true, "sha256sum": true,
	"isolate": true, "release": true,
	"quarantine": true, "restore": true,
	"block_ip": true, "unblock_ip": true,
	"list_blocked": true, "list_quarantined": true,
	"scan_packages": true,
}

func (t *GRPCTransport) StartLiveResponse(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopCh:
			return
		default:
		}
		t.mu.RLock()
		conn := t.conn
		t.mu.RUnlock()
		if conn == nil {
			time.Sleep(2 * time.Second)
			continue
		}
		err := t.runLiveResponseStream(ctx, conn)
		if err != nil {
			t.log.Warn().Err(err).Msg("live response stream ended, reconnecting...")
		}
		time.Sleep(5 * time.Second)
	}
}

func (t *GRPCTransport) runLiveResponseStream(ctx context.Context, conn *grpc.ClientConn) error {
	streamDesc := &grpc.StreamDesc{
		StreamName:   "LiveResponse",
		ServerStreams: true,
		ClientStreams: true,
	}
	stream, err := conn.NewStream(ctx, streamDesc, methodLiveResponse)
	if err != nil {
		return fmt.Errorf("open live response stream: %w", err)
	}
	regMsg := &liveResult{AgentID: t.cfg.AgentID, Status: "register"}
	if err := stream.SendMsg(regMsg); err != nil {
		return fmt.Errorf("send registration: %w", err)
	}
	t.log.Info().Msg("live response stream connected")

	for {
		cmd := &liveCommand{}
		if err := stream.RecvMsg(cmd); err != nil {
			return fmt.Errorf("recv command: %w", err)
		}
		t.log.Info().Str("command_id", cmd.CommandID).Str("action", cmd.Action).
			Strs("args", cmd.Args).Msg("received live response command")
		result := t.executeCommand(cmd)
		result.AgentID = t.cfg.AgentID
		if err := stream.SendMsg(result); err != nil {
			return fmt.Errorf("send result: %w", err)
		}
	}
}

func (t *GRPCTransport) executeCommand(cmd *liveCommand) *liveResult {
	result := &liveResult{CommandID: cmd.CommandID, Status: "completed"}

	if !allowedActions[cmd.Action] {
		result.Status = "error"
		result.Error = fmt.Sprintf("action %q not allowed", cmd.Action)
		return result
	}

	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmdName string
	var cmdArgs []string

	switch cmd.Action {
	// ── Containment actions ──
	case "isolate":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		if err := t.containment.Isolate(); err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Stdout = "Network containment activated. Only backend communication allowed."
		}
		return result
	case "release":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		if err := t.containment.Release(); err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Stdout = "Network containment released. Normal traffic restored."
		}
		return result
	case "quarantine":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "quarantine requires file path"
			return result
		}
		path, err := t.containment.QuarantineFile(cmd.Args[0])
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Stdout = fmt.Sprintf("File quarantined: %s -> %s", cmd.Args[0], path)
		}
		return result
	case "restore":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "restore requires quarantine name"
			return result
		}
		if err := t.containment.RestoreFile(cmd.Args[0]); err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Stdout = fmt.Sprintf("File restored: %s", cmd.Args[0])
		}
		return result
	case "block_ip":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "block_ip requires IP address"
			return result
		}
		if err := t.containment.BlockIP(cmd.Args[0]); err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Stdout = fmt.Sprintf("IP %s blocked", cmd.Args[0])
		}
		return result
	case "unblock_ip":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "unblock_ip requires IP address"
			return result
		}
		if err := t.containment.UnblockIP(cmd.Args[0]); err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Stdout = fmt.Sprintf("IP %s unblocked", cmd.Args[0])
		}
		return result
	case "list_blocked":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		ips := t.containment.ListBlockedIPs()
		if len(ips) == 0 {
			result.Stdout = "No IPs currently blocked"
		} else {
			result.Stdout = strings.Join(ips, "\n")
		}
		return result
	case "list_quarantined":
		if t.containment == nil {
			result.Status = "error"
			result.Error = "containment not configured"
			return result
		}
		jsonStr, err := t.containment.ListQuarantinedJSON()
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
			return result
		}
		if jsonStr == "[]" {
			result.Stdout = "No files currently quarantined"
		} else {
			result.Stdout = jsonStr
		}
		return result

	// ── Windows command equivalents ──
	case "exec":
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "exec requires at least one argument"
			return result
		}
		cmdName = cmd.Args[0]
		cmdArgs = cmd.Args[1:]
	case "ps":
		cmdName = "tasklist"
		cmdArgs = append([]string{"/v"}, cmd.Args...)
	case "ls":
		cmdName = "cmd.exe"
		dirArgs := []string{"/c", "dir", "/a"}
		cmdArgs = append(dirArgs, cmd.Args...)
	case "cat":
		cmdName = "cmd.exe"
		cmdArgs = append([]string{"/c", "type"}, cmd.Args...)
	case "kill":
		cmdName = "taskkill"
		if len(cmd.Args) > 0 {
			cmdArgs = []string{"/PID", cmd.Args[0], "/F"}
		}
	case "netstat":
		cmdName = "netstat"
		cmdArgs = append([]string{"-ano"}, cmd.Args...)
	case "df":
		cmdName = "wmic"
		cmdArgs = []string{"logicaldisk", "get", "caption,freespace,size,filesystem", "/format:csv"}
	case "who":
		cmdName = "query"
		cmdArgs = append([]string{"user"}, cmd.Args...)
	case "id":
		cmdName = "whoami"
		cmdArgs = append([]string{"/all"}, cmd.Args...)
	case "uname":
		cmdName = "systeminfo"
		cmdArgs = cmd.Args
	case "uptime":
		cmdName = "cmd.exe"
		cmdArgs = []string{"/c", "net", "statistics", "server"}
	case "stat":
		cmdName = "cmd.exe"
		cmdArgs = append([]string{"/c", "fsutil", "file", "queryFileNameById"}, cmd.Args...)
	case "find":
		cmdName = "where"
		cmdArgs = append([]string{"/r"}, cmd.Args...)
	case "md5sum":
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "md5sum requires file path"
			return result
		}
		cmdName = "certutil"
		cmdArgs = []string{"-hashfile", cmd.Args[0], "MD5"}
	case "sha256sum":
		if len(cmd.Args) == 0 {
			result.Status = "error"
			result.Error = "sha256sum requires file path"
			return result
		}
		cmdName = "certutil"
		cmdArgs = []string{"-hashfile", cmd.Args[0], "SHA256"}
	case "scan_packages":
		cmdName = "wmic"
		cmdArgs = []string{"product", "get", "name,version", "/format:csv"}
	default:
		result.Status = "error"
		result.Error = fmt.Sprintf("unknown action: %s", cmd.Action)
		return result
	}

	// Block dangerous patterns.
	fullCmd := cmdName + " " + strings.Join(cmdArgs, " ")
	for _, bad := range []string{
		"format c:", "rd /s /q", "del /f /s /q C:\\",
		"shutdown", "restart-computer", "stop-computer",
	} {
		if strings.Contains(strings.ToLower(fullCmd), strings.ToLower(bad)) {
			result.Status = "error"
			result.Error = "command blocked: contains dangerous pattern"
			return result
		}
	}

	execCmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err := execCmd.Run()
	result.Stdout = truncate(stdout.String(), 1<<20)
	result.Stderr = truncate(stderr.String(), 64<<10)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
			result.Error = fmt.Sprintf("command timed out after %v", timeout)
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Status = "error"
			result.Error = err.Error()
		}
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}
