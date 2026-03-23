// Package configver provides an atomic config version counter shared between
// the ingest (gRPC) and API (REST) servers. When detection rules, suppressions,
// or other policy objects change, the API server calls Bump(). The ingest
// server returns Get() in heartbeat/register responses so agents can detect
// the change and reload.
package configver

import (
	"fmt"
	"sync/atomic"
)

var version int64 = 1

// Get returns the current config version as a string.
func Get() string {
	return fmt.Sprintf("%d", atomic.LoadInt64(&version))
}

// Bump increments the config version and returns the new value as a string.
func Bump() string {
	v := atomic.AddInt64(&version, 1)
	return fmt.Sprintf("%d", v)
}
