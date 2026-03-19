// internal/liveresponse/session.go
// Manages live response sessions between the REST API and connected agents.
// The backend keeps a map of agent_id → command channel. When the REST API
// sends a command, it's routed through the channel to the agent's gRPC stream.

package liveresponse

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Command represents a live response command sent to an agent.
type Command struct {
	ID      string   `json:"command_id"`
	Action  string   `json:"action"`  // exec, kill, ls, cat, ps, netstat, download
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"` // seconds
}

// Result is the agent's response to a command.
type Result struct {
	CommandID string `json:"command_id"`
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`  // running, completed, error, timeout
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Error     string `json:"error,omitempty"`
}

// agentSession tracks a single connected agent's live response channel.
type agentSession struct {
	agentID  string
	cmdCh    chan Command          // backend → agent
	resultCh map[string]chan Result // command_id → result channel
	mu       sync.Mutex
}

// Manager manages all active live response sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*agentSession // agent_id → session
	log      zerolog.Logger
}

// NewManager creates a live response session manager.
func NewManager(log zerolog.Logger) *Manager {
	return &Manager{
		sessions: make(map[string]*agentSession),
		log:      log.With().Str("component", "liveresponse").Logger(),
	}
}

// allowedActions is the set of commands agents are allowed to execute.
var allowedActions = map[string]bool{
	"exec":    true,
	"ps":      true,
	"ls":      true,
	"cat":     true,
	"kill":    true,
	"netstat": true,
	"df":      true,
	"who":     true,
	"id":      true,
	"uname":   true,
	"uptime":  true,
	"stat":    true,
	"find":    true,
	"md5sum":  true,
	"sha256sum": true,
	"isolate":   true,
	"release":   true,
}

// RegisterAgent registers an agent's live response session.
// Returns the command channel that the gRPC handler reads from.
func (m *Manager) RegisterAgent(agentID string) <-chan Command {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess := &agentSession{
		agentID:  agentID,
		cmdCh:    make(chan Command, 32),
		resultCh: make(map[string]chan Result),
	}
	m.sessions[agentID] = sess
	m.log.Info().Str("agent_id", agentID).Msg("agent connected for live response")
	return sess.cmdCh
}

// UnregisterAgent removes an agent's session.
func (m *Manager) UnregisterAgent(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sess, ok := m.sessions[agentID]; ok {
		close(sess.cmdCh)
		sess.mu.Lock()
		for _, ch := range sess.resultCh {
			close(ch)
		}
		sess.mu.Unlock()
		delete(m.sessions, agentID)
		m.log.Info().Str("agent_id", agentID).Msg("agent disconnected from live response")
	}
}

// IsConnected checks if an agent has an active live response session.
func (m *Manager) IsConnected(agentID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.sessions[agentID]
	return ok
}

// ConnectedAgents returns the list of agent IDs with active sessions.
func (m *Manager) ConnectedAgents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}

// SendCommand sends a command to an agent and waits for the result.
func (m *Manager) SendCommand(ctx context.Context, agentID string, action string, args []string, timeoutSecs int) (*Result, error) {
	if !allowedActions[action] {
		return nil, fmt.Errorf("action %q is not allowed", action)
	}

	m.mu.RLock()
	sess, ok := m.sessions[agentID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("agent %s is not connected for live response", agentID)
	}

	if timeoutSecs <= 0 {
		timeoutSecs = 30
	}

	cmd := Command{
		ID:      "cmd-" + uuid.New().String(),
		Action:  action,
		Args:    args,
		Timeout: timeoutSecs,
	}

	// Create result channel before sending command.
	resultCh := make(chan Result, 1)
	sess.mu.Lock()
	sess.resultCh[cmd.ID] = resultCh
	sess.mu.Unlock()

	defer func() {
		sess.mu.Lock()
		delete(sess.resultCh, cmd.ID)
		sess.mu.Unlock()
	}()

	// Send command to agent.
	select {
	case sess.cmdCh <- cmd:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("agent %s command queue full", agentID)
	}

	m.log.Info().
		Str("agent_id", agentID).
		Str("command_id", cmd.ID).
		Str("action", action).
		Strs("args", args).
		Msg("command sent to agent")

	// Wait for result with timeout.
	timeout := time.Duration(timeoutSecs+5) * time.Second
	select {
	case result, ok := <-resultCh:
		if !ok {
			return nil, fmt.Errorf("agent %s disconnected", agentID)
		}
		return &result, nil
	case <-time.After(timeout):
		return &Result{
			CommandID: cmd.ID,
			AgentID:   agentID,
			Status:    "timeout",
			Error:     fmt.Sprintf("command timed out after %ds", timeoutSecs),
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DeliverResult routes a result from an agent back to the waiting caller.
func (m *Manager) DeliverResult(agentID string, result Result) {
	m.mu.RLock()
	sess, ok := m.sessions[agentID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	sess.mu.Lock()
	ch, ok := sess.resultCh[result.CommandID]
	sess.mu.Unlock()
	if ok {
		select {
		case ch <- result:
		default:
		}
	}
}
