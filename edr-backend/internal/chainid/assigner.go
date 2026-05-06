// Package chainid assigns deterministic causal chain IDs to events,
// implementing the TraceGuard ChainID feature (SentinelOne Storyline equivalent).
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

// cacheEntry stores a chain ID with the time it was inserted, for eviction.
type cacheEntry struct {
	chainID    string
	insertedAt time.Time
}

// Assigner maintains a per-agent PID→chainID cache and assigns chain IDs to
// incoming events based on process ancestry embedded in PROCESS_EXEC payloads.
type Assigner struct {
	mu    sync.RWMutex
	cache map[string]map[uint32]*cacheEntry // agentID → pid → entry
}

// New returns a ready-to-use Assigner with a background eviction goroutine.
func New() *Assigner {
	a := &Assigner{
		cache: make(map[string]map[uint32]*cacheEntry),
	}
	go a.evict()
	return a
}

// processContext mirrors the JSON shape emitted by the agent for ProcessContext.
type processContext struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	Cmdline   string    `json:"cmdline"`
	StartTime time.Time `json:"start_time"`
}

// processExecPayload is the subset of ProcessExecEvent we need.
type processExecPayload struct {
	Process  processContext   `json:"process"`
	Ancestry []processContext `json:"ancestry"`
}

// processForkPayload extracts parent and child PIDs from PROCESS_FORK events.
type processForkPayload struct {
	Process struct {
		PID uint32 `json:"pid"`
	} `json:"process"`
	ParentProcess struct {
		PID uint32 `json:"pid"`
	} `json:"parent_process"`
	// Some agents emit child_pid at top level.
	ChildPID uint32 `json:"child_pid"`
}

// genericPayload extracts the process PID from any event payload.
type genericPayload struct {
	Process struct {
		PID uint32 `json:"pid"`
	} `json:"process"`
}

// Assign returns the chain ID for the given event, updating the cache as needed.
// agentID is the originating agent, eventType is the OCSF-style event type string,
// and payload is the raw JSON payload bytes.
func (a *Assigner) Assign(agentID, eventType string, payload []byte) string {
	switch eventType {
	case "PROCESS_EXEC":
		return a.assignProcessExec(agentID, payload)
	case "PROCESS_FORK":
		return a.assignProcessFork(agentID, payload)
	default:
		return a.lookupByPID(agentID, payload)
	}
}

// NotifyExit removes a PID from the cache 30 seconds after the process exits
// to absorb any late-arriving events while preventing unbounded growth.
func (a *Assigner) NotifyExit(agentID string, pid uint32) {
	time.AfterFunc(30*time.Second, func() {
		a.mu.Lock()
		if m, ok := a.cache[agentID]; ok {
			delete(m, pid)
		}
		a.mu.Unlock()
	})
}

func (a *Assigner) assignProcessExec(agentID string, payload []byte) string {
	var ev processExecPayload
	if err := json.Unmarshal(payload, &ev); err != nil || ev.Process.PID == 0 {
		return ""
	}

	// Find the root process: last (oldest) ancestor, or the process itself if no ancestry.
	root := ev.Process
	if len(ev.Ancestry) > 0 {
		root = ev.Ancestry[len(ev.Ancestry)-1]
	}

	chainID := computeChainID(agentID, root.PID, root.StartTime)

	a.mu.Lock()
	if a.cache[agentID] == nil {
		a.cache[agentID] = make(map[uint32]*cacheEntry)
	}
	now := time.Now()
	entry := &cacheEntry{chainID: chainID, insertedAt: now}
	// Register all ancestor PIDs so sibling processes share the chain.
	for _, anc := range ev.Ancestry {
		if anc.PID != 0 {
			if existing, ok := a.cache[agentID][anc.PID]; !ok || existing.chainID != chainID {
				a.cache[agentID][anc.PID] = &cacheEntry{chainID: chainID, insertedAt: now}
			}
		}
	}
	a.cache[agentID][ev.Process.PID] = entry
	a.mu.Unlock()

	return chainID
}

func (a *Assigner) assignProcessFork(agentID string, payload []byte) string {
	var ev processForkPayload
	if err := json.Unmarshal(payload, &ev); err != nil {
		return a.lookupByPID(agentID, payload)
	}

	parentPID := ev.ParentProcess.PID
	childPID := ev.Process.PID
	if childPID == 0 {
		childPID = ev.ChildPID
	}

	// Look up parent's chain.
	var parentChainID string
	if parentPID != 0 {
		a.mu.RLock()
		if m, ok := a.cache[agentID]; ok {
			if e, ok := m[parentPID]; ok {
				parentChainID = e.chainID
			}
		}
		a.mu.RUnlock()
	}

	if parentChainID == "" {
		// Fall back to generic lookup using the process PID in the payload.
		return a.lookupByPID(agentID, payload)
	}

	// Register child PID → same chain as parent.
	if childPID != 0 {
		a.mu.Lock()
		if a.cache[agentID] == nil {
			a.cache[agentID] = make(map[uint32]*cacheEntry)
		}
		a.cache[agentID][childPID] = &cacheEntry{chainID: parentChainID, insertedAt: time.Now()}
		a.mu.Unlock()
	}

	return parentChainID
}

func (a *Assigner) lookupByPID(agentID string, payload []byte) string {
	var gp genericPayload
	if err := json.Unmarshal(payload, &gp); err != nil || gp.Process.PID == 0 {
		return ""
	}
	pid := gp.Process.PID

	a.mu.RLock()
	var chainID string
	if m, ok := a.cache[agentID]; ok {
		if e, ok := m[pid]; ok {
			chainID = e.chainID
		}
	}
	a.mu.RUnlock()

	if chainID != "" {
		return chainID
	}

	// No cached entry — synthesise a fallback label rooted at this unknown PID.
	prefix := agentID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	chainID = "pid:" + prefix + ":" + strconv.FormatUint(uint64(pid), 10)

	a.mu.Lock()
	if a.cache[agentID] == nil {
		a.cache[agentID] = make(map[uint32]*cacheEntry)
	}
	a.cache[agentID][pid] = &cacheEntry{chainID: chainID, insertedAt: time.Now()}
	a.mu.Unlock()

	return chainID
}

// evict runs in the background, sweeping the cache every 30 minutes and
// evicting entries older than 4 hours.
func (a *Assigner) evict() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-4 * time.Hour)
		a.mu.Lock()
		for agentID, m := range a.cache {
			for pid, entry := range m {
				if entry.insertedAt.Before(cutoff) {
					delete(m, pid)
				}
			}
			if len(m) == 0 {
				delete(a.cache, agentID)
			}
		}
		a.mu.Unlock()
	}
}

// computeChainID produces a 16-char hex ID that is deterministic and
// PID-reuse-immune (it incorporates the process start time).
func computeChainID(agentID string, rootPID uint32, rootStart time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", agentID, rootPID, rootStart.UnixNano())))
	return hex.EncodeToString(h[:])[:16]
}
