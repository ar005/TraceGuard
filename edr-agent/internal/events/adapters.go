// internal/events/adapters.go
// Compile-time interface satisfaction checks.
// EventType() and EventID() are implemented on BaseEvent in pkg/types,
// which all event structs embed — no per-type adapters needed.

package events

import "github.com/youredr/edr-agent/pkg/types"

// Compile-time checks: all event types must satisfy the Event interface.
var (
	_ Event = (*types.ProcessExecEvent)(nil)
	_ Event = (*types.ProcessExitEvent)(nil)
	_ Event = (*types.ProcessForkEvent)(nil)
	_ Event = (*types.ProcessPtraceEvent)(nil)
	_ Event = (*types.NetworkEvent)(nil)
	_ Event = (*types.FileEvent)(nil)
	_ Event = (*types.RegistryEvent)(nil)
)
