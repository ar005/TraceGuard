// Package chainid provides agent-side chain ID assignment for TraceGuard EDR.
// Maintains a PID→chainID cache and stamps chain_id on every event before
// it is sent to the backend.
package chainid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

type cacheEntry struct {
	chainID    string
	insertedAt time.Time
}

// Assigner maintains a PID→chainID cache and assigns chain IDs to events.
type Assigner struct {
	agentID string
	mu      sync.RWMutex
	cache   map[uint32]*cacheEntry
	stopCh  chan struct{}
}

// New creates an Assigner and starts the background eviction loop.
func New(agentID string) *Assigner {
	a := &Assigner{
		agentID: agentID,
		cache:   make(map[uint32]*cacheEntry),
		stopCh:  make(chan struct{}),
	}
	go a.evict()
	return a
}

// Stop terminates the background eviction goroutine.
func (a *Assigner) Stop() {
	close(a.stopCh)
}

// ─── Internal payload shapes ──────────────────────────────────────────────────

type processContext struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	Cmdline   string    `json:"cmdline"`
	StartTime time.Time `json:"start_time"`
}

type processExecPayload struct {
	Process  processContext   `json:"process"`
	Ancestry []processContext `json:"ancestry"`
}

type processForkPayload struct {
	Process struct {
		PID uint32 `json:"pid"`
	} `json:"process"`
	ParentProcess struct {
		PID uint32 `json:"pid"`
	} `json:"parent_process"`
	ChildPID uint32 `json:"child_pid"`
}

type genericPayload struct {
	Process struct {
		PID uint32 `json:"pid"`
	} `json:"process"`
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Assign returns the chain ID for the given event type + JSON payload.
func (a *Assigner) Assign(eventType string, payload []byte) string {
	switch eventType {
	case "PROCESS_EXEC":
		return a.assignProcessExec(payload)
	case "PROCESS_FORK":
		return a.assignProcessFork(payload)
	case "PROCESS_EXIT":
		return a.handleProcessExit(payload)
	default:
		return a.lookupByPID(payload)
	}
}

// NotifyExit schedules PID removal 30 s after process exit to absorb late events.
func (a *Assigner) NotifyExit(pid uint32) {
	time.AfterFunc(30*time.Second, func() {
		a.mu.Lock()
		delete(a.cache, pid)
		a.mu.Unlock()
	})
}

// ─── Internal methods ─────────────────────────────────────────────────────────

func (a *Assigner) assignProcessExec(payload []byte) string {
	var ev processExecPayload
	if err := json.Unmarshal(payload, &ev); err != nil || ev.Process.PID == 0 {
		return ""
	}

	root := ev.Process
	if len(ev.Ancestry) > 0 {
		root = ev.Ancestry[len(ev.Ancestry)-1]
	}

	chainID := computeChainID(a.agentID, root.PID, root.StartTime)

	a.mu.Lock()
	now := time.Now()
	for _, anc := range ev.Ancestry {
		if anc.PID != 0 {
			if existing, ok := a.cache[anc.PID]; !ok || existing.chainID != chainID {
				a.cache[anc.PID] = &cacheEntry{chainID: chainID, insertedAt: now}
			}
		}
	}
	a.cache[ev.Process.PID] = &cacheEntry{chainID: chainID, insertedAt: now}
	a.mu.Unlock()

	return chainID
}

func (a *Assigner) assignProcessFork(payload []byte) string {
	var ev processForkPayload
	if err := json.Unmarshal(payload, &ev); err != nil {
		return a.lookupByPID(payload)
	}

	parentPID := ev.ParentProcess.PID
	childPID := ev.Process.PID
	if childPID == 0 {
		childPID = ev.ChildPID
	}

	if parentPID == 0 {
		return a.lookupByPID(payload)
	}
	a.mu.Lock()
	e, ok := a.cache[parentPID]
	if !ok {
		a.mu.Unlock()
		return a.lookupByPID(payload)
	}
	parentChainID := e.chainID
	if childPID != 0 {
		a.cache[childPID] = &cacheEntry{chainID: parentChainID, insertedAt: time.Now()}
	}
	a.mu.Unlock()
	return parentChainID
}

func (a *Assigner) handleProcessExit(payload []byte) string {
	chainID := a.lookupByPID(payload)
	var gp genericPayload
	if err := json.Unmarshal(payload, &gp); err == nil && gp.Process.PID != 0 {
		a.NotifyExit(gp.Process.PID)
	}
	return chainID
}

func (a *Assigner) lookupByPID(payload []byte) string {
	var gp genericPayload
	if err := json.Unmarshal(payload, &gp); err != nil || gp.Process.PID == 0 {
		return ""
	}
	pid := gp.Process.PID

	a.mu.RLock()
	if e, ok := a.cache[pid]; ok {
		id := e.chainID
		a.mu.RUnlock()
		return id
	}
	a.mu.RUnlock()

	prefix := a.agentID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	chainID := "pid:" + prefix + ":" + strconv.FormatUint(uint64(pid), 10)

	a.mu.Lock()
	a.cache[pid] = &cacheEntry{chainID: chainID, insertedAt: time.Now()}
	a.mu.Unlock()

	return chainID
}

func (a *Assigner) evict() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
		}
		cutoff := time.Now().Add(-4 * time.Hour)
		a.mu.Lock()
		for pid, entry := range a.cache {
			if entry.insertedAt.Before(cutoff) {
				delete(a.cache, pid)
			}
		}
		a.mu.Unlock()
	}
}

func computeChainID(agentID string, rootPID uint32, rootStart time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", agentID, rootPID, rootStart.UnixNano())))
	return hex.EncodeToString(h[:])[:16]
}
