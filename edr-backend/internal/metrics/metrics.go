package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Events
	EventsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "edr_events_received_total",
		Help: "Total events received from agents",
	}, []string{"event_type", "agent_id"})

	EventsStored = promauto.NewCounter(prometheus.CounterOpts{
		Name: "edr_events_stored_total",
		Help: "Total events stored in database",
	})

	EventsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "edr_events_dropped_total",
		Help: "Total events dropped (storage failure)",
	})

	// Alerts
	AlertsFired = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "edr_alerts_fired_total",
		Help: "Total alerts fired by detection engine",
	}, []string{"rule_id", "severity"})

	// Agents
	AgentsOnline = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_agents_online",
		Help: "Number of currently online agents",
	})

	AgentsTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_agents_total",
		Help: "Total registered agents",
	})

	// gRPC
	GRPCStreamsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_grpc_streams_active",
		Help: "Active gRPC event streams from agents",
	})

	HeartbeatsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "edr_heartbeats_received_total",
		Help: "Total heartbeats received from agents",
	})

	// API
	APIRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "edr_api_request_duration_seconds",
		Help:    "REST API request latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	APIRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "edr_api_requests_total",
		Help: "Total REST API requests",
	}, []string{"method", "path", "status"})

	// Detection
	DetectionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "edr_detection_duration_seconds",
		Help:    "Time to evaluate detection rules per event",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
	})

	// SSE
	SSEClientsConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_sse_clients_connected",
		Help: "Number of connected SSE browser clients",
	})

	// Database
	DBQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "edr_db_query_duration_seconds",
		Help:    "Database query latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation"})

	// XDR connectors
	XdrEventsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xdr_events_received_total",
		Help: "Total XDR events received from external connectors",
	}, []string{"source_type"})

	XdrConnectorLag = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xdr_connector_lag_seconds",
		Help: "Seconds behind real-time for each connector (file-tail connectors only)",
	}, []string{"connector_id"})
)
