package liveresponse

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestManager() *Manager {
	return NewManager(zerolog.New(os.Stderr).Level(zerolog.Disabled))
}

func TestAllowedActionsContainsExpected(t *testing.T) {
	expected := []string{
		"exec", "ps", "ls", "cat", "kill", "netstat", "df",
		"quarantine", "restore", "block_ip", "unblock_ip",
		"list_blocked", "list_quarantined", "scan_packages",
		"isolate", "release", "who", "id", "uname", "uptime",
		"stat", "find", "md5sum", "sha256sum",
	}
	for _, action := range expected {
		if !allowedActions[action] {
			t.Errorf("allowedActions missing %q", action)
		}
	}
}

func TestRegisterAndIsConnected(t *testing.T) {
	m := newTestManager()

	if m.IsConnected("agent-1") {
		t.Error("IsConnected should be false before registration")
	}

	m.RegisterAgent("agent-1")

	if !m.IsConnected("agent-1") {
		t.Error("IsConnected should be true after registration")
	}
}

func TestIsConnectedUnknownAgent(t *testing.T) {
	m := newTestManager()
	if m.IsConnected("nonexistent") {
		t.Error("IsConnected should be false for unknown agent")
	}
}

func TestConnectedAgents(t *testing.T) {
	m := newTestManager()
	m.RegisterAgent("agent-a")
	m.RegisterAgent("agent-b")
	m.RegisterAgent("agent-c")

	got := m.ConnectedAgents()
	sort.Strings(got)

	want := []string{"agent-a", "agent-b", "agent-c"}
	if len(got) != len(want) {
		t.Fatalf("ConnectedAgents length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ConnectedAgents[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUnregisterAgent(t *testing.T) {
	m := newTestManager()
	m.RegisterAgent("agent-x")

	if !m.IsConnected("agent-x") {
		t.Fatal("agent should be connected")
	}

	m.UnregisterAgent("agent-x")

	if m.IsConnected("agent-x") {
		t.Error("agent should not be connected after unregister")
	}
	if len(m.ConnectedAgents()) != 0 {
		t.Error("ConnectedAgents should be empty after unregister")
	}
}

func TestSendCommandUnregisteredAgent(t *testing.T) {
	m := newTestManager()
	ctx := context.Background()

	_, err := m.SendCommand(ctx, "no-such-agent", "ps", nil, 5)
	if err == nil {
		t.Fatal("expected error for unregistered agent")
	}
}

func TestSendCommandDisallowedAction(t *testing.T) {
	m := newTestManager()
	m.RegisterAgent("agent-1")
	ctx := context.Background()

	_, err := m.SendCommand(ctx, "agent-1", "rm", []string{"-rf", "/"}, 5)
	if err == nil {
		t.Fatal("expected error for disallowed action")
	}
}

func TestSendCommandDelivered(t *testing.T) {
	m := newTestManager()
	cmdCh := m.RegisterAgent("agent-1")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start SendCommand in a goroutine (it blocks waiting for result).
	errCh := make(chan error, 1)
	var result *Result
	go func() {
		var err error
		result, err = m.SendCommand(ctx, "agent-1", "ps", nil, 5)
		errCh <- err
	}()

	// Read the command from the agent's channel.
	select {
	case cmd := <-cmdCh:
		if cmd.Action != "ps" {
			t.Errorf("command action = %q, want %q", cmd.Action, "ps")
		}
		// Deliver a result.
		m.DeliverResult("agent-1", Result{
			CommandID: cmd.ID,
			AgentID:   "agent-1",
			Status:    "completed",
			Stdout:    "PID TTY TIME CMD",
		})
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for command on agent channel")
	}

	// Wait for SendCommand to return.
	if err := <-errCh; err != nil {
		t.Fatalf("SendCommand error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Status != "completed" {
		t.Errorf("result status = %q, want %q", result.Status, "completed")
	}
}
