// internal/correlation/ipmap.go
//
// IPMapper maintains an in-memory cache of IP → (agentID, userUID) mappings
// built from endpoint connection events.  It is updated whenever the ingest
// pipeline stores an event that carries an IP address reported by an agent,
// and queried by the Stitcher to attribute network-layer events back to an
// endpoint or identity.
//
// The cache is bounded: entries expire after MaxAge (default 30 min) and the
// map is hard-capped at MaxEntries to prevent unbounded growth.

package correlation

import (
	"net"
	"sync"
	"time"
)

// IPEntry records the last known association of an IP with an endpoint/user.
type IPEntry struct {
	AgentID   string
	UserUID   string
	UpdatedAt time.Time
}

// IPMapper maps net.IP strings → IPEntry with TTL-bounded eviction.
type IPMapper struct {
	mu         sync.RWMutex
	entries    map[string]*IPEntry // key: IP.String()
	maxEntries int
	maxAge     time.Duration
}

// NewIPMapper creates an IPMapper.  maxEntries=0 → default 50 000.
func NewIPMapper(maxEntries int, maxAge time.Duration) *IPMapper {
	if maxEntries <= 0 {
		maxEntries = 50_000
	}
	if maxAge <= 0 {
		maxAge = 30 * time.Minute
	}
	return &IPMapper{
		entries:    make(map[string]*IPEntry, 1024),
		maxEntries: maxEntries,
		maxAge:     maxAge,
	}
}

// Set records or updates an IP → (agentID, userUID) mapping.
func (m *IPMapper) Set(ip net.IP, agentID, userUID string) {
	if ip == nil {
		return
	}
	key := ip.String()
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.entries) >= m.maxEntries {
		m.evictOldestLocked()
	}
	m.entries[key] = &IPEntry{AgentID: agentID, UserUID: userUID, UpdatedAt: time.Now()}
}

// Get looks up an IP. Returns nil if the IP is unknown or the entry has expired.
func (m *IPMapper) Get(ip net.IP) *IPEntry {
	if ip == nil {
		return nil
	}
	key := ip.String()
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(e.UpdatedAt) > m.maxAge {
		m.mu.Lock()
		delete(m.entries, key)
		m.mu.Unlock()
		return nil
	}
	return e
}

// Len returns the current number of entries.
func (m *IPMapper) Len() int {
	m.mu.RLock()
	n := len(m.entries)
	m.mu.RUnlock()
	return n
}

// evictOldestLocked removes the single oldest entry. Caller must hold mu.Lock.
func (m *IPMapper) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, e := range m.entries {
		if oldestKey == "" || e.UpdatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.UpdatedAt
		}
	}
	if oldestKey != "" {
		delete(m.entries, oldestKey)
	}
}
