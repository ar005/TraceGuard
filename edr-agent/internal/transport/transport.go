// internal/transport/transport.go
//
// gRPC transport — streams events to the EDR backend.
// Uses the JSON codec (matching the backend's codec registration).
// Falls back to SQLite buffer on disconnect; replays on reconnect.

package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/keepalive"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/internal/version"
)

// ─── JSON codec ───────────────────────────────────────────────────────────────

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

type jsonCodec struct{}
func (jsonCodec) Marshal(v interface{}) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }
func (jsonCodec) Name() string                                { return "json" }

// ─── Wire types (mirror backend proto) ───────────────────────────────────────

type eventEnvelope struct {
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Timestamp int64  `json:"timestamp"`
	Payload   []byte `json:"payload"`
	OS        string `json:"os"`
	AgentVer  string `json:"agent_ver"`
}

type streamResponse struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
}

type registerRequest struct {
	AgentID  string   `json:"agent_id"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	AgentVer string   `json:"agent_ver"`
	Tags     []string `json:"tags"`
	Env      string   `json:"env"`
	Notes    string   `json:"notes"`
}

type registerResponse struct {
	Ok            bool   `json:"ok"`
	AssignedID    string `json:"assigned_id"`
	ConfigVersion string `json:"config_version"`
}

type heartbeatRequest struct {
	AgentID     string       `json:"agent_id"`
	Hostname    string       `json:"hostname"`
	Timestamp   int64        `json:"timestamp"`
	OS          string       `json:"os"`
	TaskResults []TaskResult `json:"task_results,omitempty"`
}

// TaskInstruction mirrors proto.TaskInstruction — duplicated here to keep the
// transport package self-contained without importing the backend proto package.
type TaskInstruction struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// TaskResult is sent back to the backend in the next heartbeat request.
type TaskResult struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"` // "success" | "failed"
	Output string `json:"output"`
	ErrMsg string `json:"error,omitempty"`
}

type heartbeatResponse struct {
	Ok            bool              `json:"ok"`
	ServerTime    int64             `json:"server_time"`
	ConfigVersion string            `json:"config_version"`
	PendingTasks  []TaskInstruction `json:"pending_tasks,omitempty"`
}

const (
	methodRegister     = "/edr.v1.EventService/Register"
	methodStreamEvents = "/edr.v1.EventService/StreamEvents"
	methodHeartbeat    = "/edr.v1.EventService/Heartbeat"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	BackendURL        string
	TLSCert           string
	TLSKey            string
	TLSCA             string
	AgentID           string
	Hostname          string
	Insecure          bool
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
	Tags              []string
	Env               string
	Notes             string
}

func (c *Config) applyDefaults() {
	if c.ReconnectDelay == 0    { c.ReconnectDelay = 2 * time.Second }
	if c.MaxReconnectDelay == 0 { c.MaxReconnectDelay = 60 * time.Second }
}

// ─── Transport ────────────────────────────────────────────────────────────────

// ContainmentController is implemented by the containment.Manager.
type ContainmentController interface {
	Isolate() error
	Release() error
	IsContained() bool
	QuarantineFile(filePath string) (string, error)
	RestoreFile(quarantineName string) error
	ListQuarantinedJSON() (string, error)
	BlockIP(ip string, persistent bool) error
	UnblockIP(ip string) error
	ListBlockedIPs() []string
	BlockDomain(domain string, persistent bool) error
	UnblockDomain(domain string) error
	ListBlockedDomains() []string
}

type GRPCTransport struct {
	cfg    Config
	log    zerolog.Logger
	sendCh chan []byte
	stopCh chan struct{}
	wg     sync.WaitGroup
	mu     sync.RWMutex
	conn   *grpc.ClientConn
	connected bool
	containment    ContainmentController
	configVersion  string
	onConfigChange func(newVersion string)
	onTask         func(TaskInstruction)
	resultsMu      sync.Mutex
	pendingResults []TaskResult
}

func New(cfg Config, log zerolog.Logger) *GRPCTransport {
	cfg.applyDefaults()
	return &GRPCTransport{
		cfg:    cfg,
		log:    log.With().Str("component", "transport").Logger(),
		sendCh: make(chan []byte, 8192),
		stopCh: make(chan struct{}),
	}
}

// SetContainment sets the containment controller for live response isolation commands.
func (t *GRPCTransport) SetContainment(c ContainmentController) {
	t.containment = c
}

// OnConfigChange registers a callback that is invoked when the backend
// reports a new config version in a heartbeat or register response.
func (t *GRPCTransport) OnConfigChange(fn func(newVersion string)) {
	t.onConfigChange = fn
}

// OnTask registers a callback invoked for each task delivered by the backend.
func (t *GRPCTransport) OnTask(fn func(TaskInstruction)) {
	t.onTask = fn
}

// ReportTaskResult queues an execution result to be sent on the next heartbeat.
func (t *GRPCTransport) ReportTaskResult(r TaskResult) {
	t.resultsMu.Lock()
	t.pendingResults = append(t.pendingResults, r)
	t.resultsMu.Unlock()
}

func (t *GRPCTransport) Start(ctx context.Context) error {
	if err := t.connect(ctx); err != nil {
		t.log.Warn().Err(err).Msg("initial connect failed — will retry in background")
	}
	t.wg.Add(2)
	go t.sendLoop(ctx)
	go t.heartbeatLoop(ctx)
	return nil
}

func (t *GRPCTransport) Send(event events.Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		t.log.Error().Err(err).Msg("marshal event")
		return
	}
	env, err := json.Marshal(&eventEnvelope{
		AgentID:   t.cfg.AgentID,
		Hostname:  t.cfg.Hostname,
		EventID:   event.EventID(),
		EventType: event.EventType(),
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
		OS:        "linux",
		AgentVer:  version.Short(),
	})
	if err != nil {
		return
	}
	select {
	case t.sendCh <- env:
	default:
		// Channel full — drop; SQLite buffer has the event.
	}
}

func (t *GRPCTransport) Stop() {
	close(t.stopCh)
	t.wg.Wait()
	t.mu.RLock()
	if t.conn != nil {
		t.conn.Close()
	}
	t.mu.RUnlock()
}

func (t *GRPCTransport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected
}

func (t *GRPCTransport) connect(ctx context.Context) error {
	creds, err := t.buildCredentials()
	if err != nil {
		return err
	}
	//nolint:staticcheck // DialContext is fine here
	conn, err := grpc.DialContext(ctx, t.cfg.BackendURL,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype("json")),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 30 * time.Second, Timeout: 10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("dial %s: %w", t.cfg.BackendURL, err)
	}

	// Register agent.
	var regResp registerResponse
	err = conn.Invoke(ctx, methodRegister, &registerRequest{
		AgentID:  t.cfg.AgentID,
		Hostname: t.cfg.Hostname,
		OS:       "linux",
		AgentVer: version.Short(),
		Tags:     t.cfg.Tags,
		Env:      t.cfg.Env,
		Notes:    t.cfg.Notes,
	}, &regResp, grpc.CallContentSubtype("json"))
	if err != nil {
		conn.Close()
		return fmt.Errorf("register: %w", err)
	}

	t.log.Info().Str("backend", t.cfg.BackendURL).Msg("connected and registered")

	// Check if backend config version changed during registration.
	if regResp.ConfigVersion != "" && regResp.ConfigVersion != t.configVersion {
		old := t.configVersion
		t.configVersion = regResp.ConfigVersion
		t.log.Info().Str("old", old).Str("new", regResp.ConfigVersion).Msg("backend config version changed")
		if t.onConfigChange != nil {
			t.onConfigChange(regResp.ConfigVersion)
		}
	}

	t.mu.Lock()
	if t.conn != nil {
		t.conn.Close()
	}
	t.conn = conn
	t.connected = true
	t.mu.Unlock()
	return nil
}

func (t *GRPCTransport) sendLoop(ctx context.Context) {
	defer t.wg.Done()
	delay := t.cfg.ReconnectDelay
	var stream grpc.ClientStream

	openStream := func() {
		t.mu.RLock()
		conn, ok := t.conn, t.connected
		t.mu.RUnlock()
		if !ok || conn == nil {
			return
		}
		var err error
		stream, err = conn.NewStream(ctx,
			&grpc.StreamDesc{ClientStreams: true},
			methodStreamEvents,
			grpc.CallContentSubtype("json"),
		)
		if err != nil {
			t.log.Warn().Err(err).Msg("open event stream failed")
			stream = nil
		}
	}
	openStream()

	const flushInterval = 50 * time.Millisecond
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()
	pending := make([]*eventEnvelope, 0, 50)

	flushPending := func() {
		if stream == nil || len(pending) == 0 {
			pending = pending[:0]
			return
		}
		for _, e := range pending {
			if err := stream.SendMsg(e); err != nil {
				t.log.Warn().Err(err).Msg("send failed — will reconnect")
				stream = nil
				t.mu.Lock()
				t.connected = false
				t.mu.Unlock()
				break
			}
		}
		pending = pending[:0]
	}

	for {
		select {
		case <-t.stopCh:
			flushPending()
			return
		case <-ctx.Done():
			flushPending()
			return
		case <-flushTicker.C:
			flushPending()
		case data := <-t.sendCh:
			if stream == nil {
				if err := t.connect(ctx); err != nil {
					time.Sleep(delay)
					if delay*2 < t.cfg.MaxReconnectDelay {
						delay *= 2
					} else {
						delay = t.cfg.MaxReconnectDelay
					}
					continue
				}
				delay = t.cfg.ReconnectDelay
				openStream()
			}
			if stream == nil {
				continue
			}
			var env eventEnvelope
			if err := json.Unmarshal(data, &env); err != nil {
				continue
			}
			pending = append(pending, &env)
			if len(pending) >= 50 {
				flushPending()
			}
		}
	}
}

func (t *GRPCTransport) heartbeatLoop(ctx context.Context) {
	defer t.wg.Done()
	ticker := time.NewTicker(20 * time.Second) // every 20s — backend timeout is typically 60s
	defer ticker.Stop()
	reconnectDelay := 2 * time.Second
	// Immediate first attempt — don't wait 20s for first tick
	go func() {
		time.Sleep(2 * time.Second) // brief delay for startup
		if !t.IsConnected() {
			if err := t.connect(ctx); err != nil {
				t.log.Warn().Err(err).Msg("startup reconnect failed")
			}
		}
	}()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// If disconnected, try to reconnect proactively
			if !t.IsConnected() {
				t.log.Info().Msg("not connected — attempting reconnect")
				if err := t.connect(ctx); err != nil {
					t.log.Warn().Err(err).Dur("retry_in", reconnectDelay).Msg("reconnect failed")
					time.Sleep(reconnectDelay)
					if reconnectDelay < 60*time.Second {
						reconnectDelay *= 2
					}
				} else {
					reconnectDelay = 5 * time.Second
				}
				continue
			}
			reconnectDelay = 5 * time.Second
			t.mu.RLock()
			conn := t.conn
			t.mu.RUnlock()
			if conn == nil {
				continue
			}
			// Drain accumulated task results to include in this heartbeat.
			t.resultsMu.Lock()
			results := t.pendingResults
			t.pendingResults = nil
			t.resultsMu.Unlock()

			hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			var resp heartbeatResponse
			err := conn.Invoke(hbCtx, methodHeartbeat, &heartbeatRequest{
				AgentID: t.cfg.AgentID, Hostname: t.cfg.Hostname,
				Timestamp: time.Now().UnixNano(), OS: "linux",
				TaskResults: results,
			}, &resp, grpc.CallContentSubtype("json"))
			cancel()
			if err != nil {
				t.log.Warn().Err(err).Msg("heartbeat failed — marking disconnected")
				t.mu.Lock()
				t.connected = false
				t.mu.Unlock()
				// Re-queue results so they are not lost on transient failures.
				if len(results) > 0 {
					t.resultsMu.Lock()
					t.pendingResults = append(results, t.pendingResults...)
					t.resultsMu.Unlock()
				}
			} else {
				t.log.Debug().Msg("heartbeat ok")
				// Check if backend config version changed.
				if resp.ConfigVersion != "" && resp.ConfigVersion != t.configVersion {
					old := t.configVersion
					t.configVersion = resp.ConfigVersion
					t.log.Info().Str("old", old).Str("new", resp.ConfigVersion).Msg("backend config version changed")
					if t.onConfigChange != nil {
						t.onConfigChange(resp.ConfigVersion)
					}
				}
				// Dispatch any tasks delivered by the backend.
				for _, task := range resp.PendingTasks {
					t.log.Info().Str("task_id", task.ID).Str("type", task.Type).Str("name", task.Name).Msg("task received")
					if t.onTask != nil {
						go t.onTask(task)
					}
				}
			}
		}
	}
}

func (t *GRPCTransport) buildCredentials() (credentials.TransportCredentials, error) {
	if t.cfg.Insecure {
		t.log.Warn().Msg("TLS disabled — INSECURE (dev only)")
		return insecure.NewCredentials(), nil
	}
	if t.cfg.TLSCert == "" {
		return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13}), nil
	}
	cert, err := tls.LoadX509KeyPair(t.cfg.TLSCert, t.cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if t.cfg.TLSCA != "" {
		pem, err := os.ReadFile(t.cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}
