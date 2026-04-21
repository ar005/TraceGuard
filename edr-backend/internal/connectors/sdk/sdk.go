// internal/connectors/sdk/sdk.go
//
// Connector SDK — exported interface and base types for third-party connectors.
//
// Third-party connectors implement the Connector interface and register via
// connectors.Registry.Register(). The SDK provides the interface contract so
// external modules can import sdk/ without forking the backend.
//
// Versioning: this package follows semantic versioning. Breaking interface
// changes increment the major version in the module path.

package sdk

import (
	"context"
	"time"
)

// Version is the SDK interface version. Connectors must declare compatibility.
const Version = "1.0.0"

// Event is a normalized connector event in OCSF-compatible form.
// Connectors produce Events; the backend ingest path consumes them.
type Event struct {
	// ClassUID is the OCSF class identifier (e.g. 4001 = Network Activity).
	ClassUID int32 `json:"class_uid"`
	// CategoryUID is the OCSF category (e.g. 4 = Network Activity).
	CategoryUID int32 `json:"category_uid"`

	// SourceType identifies the connector category: endpoint, network, cloud, identity.
	SourceType string `json:"source_type"`
	// SourceID is the xdr_sources.id of the connector that produced this event.
	SourceID string `json:"source_id"`

	// AgentID maps to the EDR agent_id (empty for non-endpoint sources).
	AgentID string `json:"agent_id,omitempty"`
	// UserUID is the normalized user identifier (email or UPN).
	UserUID string `json:"user_uid,omitempty"`
	// Hostname is the originating host.
	Hostname string `json:"hostname,omitempty"`

	// SrcIP / DstIP are the network endpoints (optional).
	SrcIP string `json:"src_ip,omitempty"`
	DstIP string `json:"dst_ip,omitempty"`
	SrcPort int   `json:"src_port,omitempty"`
	DstPort int   `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`

	// EventType is the TraceGuard canonical event type string (PROCESS_EXEC, etc.)
	EventType string `json:"event_type"`
	// Timestamp is when the event occurred on the source system.
	Timestamp time.Time `json:"timestamp"`

	// RawPayload is the connector-specific raw event for passthrough to the events table.
	RawPayload map[string]interface{} `json:"raw,omitempty"`
}

// HealthStatus is returned by Connector.Health().
type HealthStatus struct {
	// Healthy indicates the connector can reach its data source.
	Healthy bool `json:"healthy"`
	// Message provides detail on the health state.
	Message string `json:"message,omitempty"`
	// LastEventAt is when the connector last produced an event (zero if never).
	LastEventAt time.Time `json:"last_event_at,omitempty"`
	// EventsTotal is the total number of events produced since Start().
	EventsTotal int64 `json:"events_total"`
}

// Config is a generic map of connector configuration key-value pairs loaded
// from xdr_sources.config (JSON). Keys are connector-specific.
type Config map[string]interface{}

// Get returns a string value from the config map, or "" if absent.
func (c Config) Get(key string) string {
	if v, ok := c[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetBool returns a bool value from config, defaulting to false.
func (c Config) GetBool(key string) bool {
	if v, ok := c[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// Connector is the interface all TraceGuard data-source connectors must implement.
// Register instances with connectors.Registry.Register().
type Connector interface {
	// Name returns the connector's unique identifier (e.g. "zeek", "okta").
	Name() string

	// SourceType returns the OCSF source category: "endpoint", "network", "cloud", "identity".
	SourceType() string

	// Configure initialises the connector with the configuration stored in
	// xdr_sources.config. Called once before Start().
	Configure(cfg Config) error

	// Start begins producing events. The connector sends events to the provided
	// channel until ctx is cancelled or an unrecoverable error occurs.
	// Start must be non-blocking — launch goroutines internally.
	Start(ctx context.Context, out chan<- Event) error

	// Stop performs graceful shutdown. The connector must drain in-flight events
	// and close any open connections. Called after ctx is cancelled.
	Stop() error

	// Health returns the current health status of the connector.
	Health() HealthStatus
}

// BaseConnector provides default no-op implementations of optional methods.
// Embed it in your connector struct to avoid implementing every method.
type BaseConnector struct {
	eventsTotal int64
	lastEvent   time.Time
}

func (b *BaseConnector) RecordEvent() {
	b.eventsTotal++
	b.lastEvent = time.Now()
}

func (b *BaseConnector) Health() HealthStatus {
	return HealthStatus{
		Healthy:     true,
		LastEventAt: b.lastEvent,
		EventsTotal: b.eventsTotal,
	}
}

func (b *BaseConnector) Stop() error { return nil }
