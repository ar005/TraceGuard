package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestMetricVariablesNotNil(t *testing.T) {
	vars := map[string]interface{}{
		"EventsReceived":      EventsReceived,
		"EventsStored":        EventsStored,
		"EventsDropped":       EventsDropped,
		"AlertsFired":         AlertsFired,
		"AgentsOnline":        AgentsOnline,
		"AgentsTotal":         AgentsTotal,
		"GRPCStreamsActive":   GRPCStreamsActive,
		"HeartbeatsReceived":  HeartbeatsReceived,
		"APIRequestDuration":  APIRequestDuration,
		"APIRequestsTotal":    APIRequestsTotal,
		"DetectionDuration":   DetectionDuration,
		"SSEClientsConnected": SSEClientsConnected,
		"DBQueryDuration":     DBQueryDuration,
	}
	for name, v := range vars {
		if v == nil {
			t.Errorf("%s is nil", name)
		}
	}
}

func TestCounterIncrement(t *testing.T) {
	// Use EventsStored as a simple counter.
	before := getCounterValue(t, EventsStored)
	EventsStored.Inc()
	after := getCounterValue(t, EventsStored)

	if after-before != 1 {
		t.Errorf("counter increment: diff = %f, want 1", after-before)
	}
}

func TestCounterVecIncrement(t *testing.T) {
	EventsReceived.WithLabelValues("PROCESS_EXEC", "agent-test").Inc()
	EventsReceived.WithLabelValues("PROCESS_EXEC", "agent-test").Inc()

	m := &dto.Metric{}
	if err := EventsReceived.WithLabelValues("PROCESS_EXEC", "agent-test").Write(m); err != nil {
		t.Fatalf("Write metric: %v", err)
	}
	if m.Counter == nil || *m.Counter.Value < 2 {
		t.Errorf("counter vec value = %v, want >= 2", m.Counter)
	}
}

func TestGaugeSet(t *testing.T) {
	AgentsOnline.Set(42)

	m := &dto.Metric{}
	if err := AgentsOnline.Write(m); err != nil {
		t.Fatalf("Write metric: %v", err)
	}
	if m.Gauge == nil || *m.Gauge.Value != 42 {
		t.Errorf("gauge value = %v, want 42", m.Gauge)
	}
}

func TestHistogramObserve(t *testing.T) {
	DetectionDuration.Observe(0.005)
	DetectionDuration.Observe(0.010)

	m := &dto.Metric{}
	if err := DetectionDuration.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("Write metric: %v", err)
	}
	if m.Histogram == nil || *m.Histogram.SampleCount < 2 {
		t.Errorf("histogram sample count = %v, want >= 2", m.Histogram)
	}
}

// getCounterValue reads the current value of a simple Counter.
func getCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("Write counter: %v", err)
	}
	return *m.Counter.Value
}
