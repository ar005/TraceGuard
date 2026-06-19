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
	ChainID   string `json:"chain_id,omitempty"`
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
	APIKey            string
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
	Tags              []string
	Env               string
	Notes             string
}

// apiKeyCredentials implements credentials.PerRPCCredentials, sending the
// configured API key as an Authorization: Bearer header on every RPC.
type apiKeyCredentials struct{ key string }

func (a apiKeyCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + a.key}, nil
}
func (a apiKeyCredentials) RequireTransportSecurity() bool { return false }

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

	// Backing SQLite buffer (optional). When set, the transport:
	//   - drains unsent rows on every successful (re)connect, oldest first,
	//   - calls MarkSent([ids]) batched every 2s for events shipped via
	//     the live sendCh, so durable backlog stops growing during normal
	//     operation.
	buf       BufferReader
	sentMu    sync.Mutex
	sentBatch []string
}

// BufferReader is the subset of the local SQLite buffer the transport needs
// to replay unsent events on reconnect and clear durable rows once shipped.
type BufferReader interface {
	ReadUnsent(limit int) ([]BufferedEnvelope, error)
	MarkSent(eventIDs []string) error
}

// BufferedEnvelope mirrors the buffer.BufferedEvent shape; the agent adapts
// between the two so transport stays decoupled from the buffer package.
type BufferedEnvelope struct {
	EventID   string
	EventType string
	Timestamp int64
	Payload   []byte // JSON of the original events.Event (carries chain_id)
}

// SetBuffer wires the durable buffer. Safe to call before or after Start.
func (t *GRPCTransport) SetBuffer(b BufferReader) { t.buf = b }

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

const maxPendingResults = 1000

// ReportTaskResult queues an execution result to be sent on the next heartbeat.
// Drops oldest entries if the queue exceeds maxPendingResults to prevent unbounded growth.
func (t *GRPCTransport) ReportTaskResult(r TaskResult) {
	t.resultsMu.Lock()
	t.pendingResults = append(t.pendingResults, r)
	if len(t.pendingResults) > maxPendingResults {
		t.pendingResults = t.pendingResults[len(t.pendingResults)-maxPendingResults:]
	}
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
		ChainID:   event.GetChainID(),
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
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype("json")),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 30 * time.Second, Timeout: 10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if t.cfg.APIKey != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{t.cfg.APIKey}))
	}
	//nolint:staticcheck // DialContext is fine here
	conn, err := grpc.DialContext(ctx, t.cfg.BackendURL, dialOpts...)
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
			return
		}
		// Drain durable backlog before resuming live sends. Replays oldest
		// rows first via the same stream; rows that ship successfully are
		// marked sent in the buffer so the next reconnect doesn't replay
		// them again.
		t.drainBacklog(&stream)
	}
	openStream()

	const flushInterval = 50 * time.Millisecond
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()
	// Coalesce MarkSent calls so we don't hit SQLite for every event.
	markTicker := time.NewTicker(2 * time.Second)
	defer markTicker.Stop()
	pending := make([]*eventEnvelope, 0, 50)

	flushPending := func() {
		if len(pending) == 0 {
			return
		}
		if stream == nil {
			// No stream — keep pending in the in-memory queue; the SQLite
			// buffer also has a copy (live path writes there first), so
			// drainBacklog on reconnect will replay them.
			return
		}
		// Tracks which events shipped before any error, so we can record
		// them as sent in the buffer even if a later event in the batch
		// fails. Without this, a single late SendMsg failure would lose the
		// "already shipped" tail and trigger duplicate replay on reconnect.
		shipped := make([]string, 0, len(pending))
		sentCount := 0
		for _, e := range pending {
			if err := stream.SendMsg(e); err != nil {
				t.log.Warn().Err(err).Msg("send failed — will reconnect")
				stream = nil
				t.mu.Lock()
				t.connected = false
				t.mu.Unlock()
				break
			}
			shipped = append(shipped, e.EventID)
			sentCount++
		}
		// Drop only the events that actually shipped. Anything past the
		// break stays queued so the next flush after reconnect retries it.
		pending = append(pending[:0], pending[sentCount:]...)
		if len(shipped) > 0 {
			t.queueMarkSent(shipped)
		}
	}

	for {
		select {
		case <-t.stopCh:
			flushPending()
			t.flushMarkSent()
			return
		case <-ctx.Done():
			flushPending()
			t.flushMarkSent()
			return
		case <-flushTicker.C:
			// If the connection came back via the heartbeat path but no
			// live events have arrived since, open the stream now so the
			// SQLite backlog drains promptly instead of waiting for the
			// next event.
			if stream == nil && t.IsConnected() {
				openStream()
			}
			flushPending()
		case <-markTicker.C:
			t.flushMarkSent()
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

// queueMarkSent appends event IDs to a batch that flushMarkSent ships to the
// buffer; never blocks the send loop on SQLite I/O.
func (t *GRPCTransport) queueMarkSent(ids []string) {
	if t.buf == nil || len(ids) == 0 {
		return
	}
	t.sentMu.Lock()
	t.sentBatch = append(t.sentBatch, ids...)
	t.sentMu.Unlock()
}

func (t *GRPCTransport) flushMarkSent() {
	if t.buf == nil {
		return
	}
	t.sentMu.Lock()
	batch := t.sentBatch
	t.sentBatch = nil
	t.sentMu.Unlock()
	if len(batch) == 0 {
		return
	}
	if err := t.buf.MarkSent(batch); err != nil {
		t.log.Warn().Err(err).Int("count", len(batch)).Msg("buffer: mark sent failed (will retry next reconnect)")
		// Put the IDs back; the buffer will see them again next replay.
		t.sentMu.Lock()
		t.sentBatch = append(batch, t.sentBatch...)
		t.sentMu.Unlock()
	}
}

// drainBacklog ships every unsent buffer row through the supplied stream in
// order, oldest first. Stops early if a send fails (caller will reconnect).
// Marks each successfully-shipped row as sent so the next reconnect skips it.
func (t *GRPCTransport) drainBacklog(stream *grpc.ClientStream) {
	if t.buf == nil || *stream == nil {
		return
	}
	const pageSize = 500
	total := 0
	for {
		rows, err := t.buf.ReadUnsent(pageSize)
		if err != nil {
			t.log.Warn().Err(err).Msg("buffer: read unsent failed")
			return
		}
		if len(rows) == 0 {
			break
		}
		shipped := make([]string, 0, len(rows))
		for _, r := range rows {
			// Reconstruct an envelope using the current agent identity. The
			// stored payload already carries chain_id inside the events.Event
			// JSON, so the backend sees the same shape as a live send.
			env := &eventEnvelope{
				AgentID:   t.cfg.AgentID,
				Hostname:  t.cfg.Hostname,
				EventID:   r.EventID,
				EventType: r.EventType,
				Timestamp: r.Timestamp,
				Payload:   r.Payload,
				OS:        "linux",
				AgentVer:  version.Short(),
				ChainID:   extractChainID(r.Payload),
			}
			if err := (*stream).SendMsg(env); err != nil {
				t.log.Warn().Err(err).Int("shipped_this_round", len(shipped)).Msg("backlog drain interrupted")
				*stream = nil
				t.mu.Lock()
				t.connected = false
				t.mu.Unlock()
				if len(shipped) > 0 {
					t.queueMarkSent(shipped)
				}
				return
			}
			shipped = append(shipped, r.EventID)
		}
		total += len(shipped)
		t.queueMarkSent(shipped)
		if len(rows) < pageSize {
			break
		}
	}
	if total > 0 {
		t.log.Info().Int("count", total).Msg("buffer: replayed offline backlog to backend")
		// Flush MarkSent immediately so the rows are clear before the next
		// failure can re-queue them.
		t.flushMarkSent()
	}
}

// extractChainID pulls the chain_id field out of a serialized events.Event
// without needing the concrete type. Returns "" if absent.
func extractChainID(payload []byte) string {
	var probe struct {
		ChainID string `json:"chain_id"`
	}
	_ = json.Unmarshal(payload, &probe)
	return probe.ChainID
}

func (t *GRPCTransport) heartbeatLoop(ctx context.Context) {
	defer t.wg.Done()
	ticker := time.NewTicker(20 * time.Second) // every 20s — backend timeout is typically 60s
	defer ticker.Stop()
	reconnectDelay := 2 * time.Second
	// Immediate first attempt — don't wait 20s for first tick
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		select {
		case <-time.After(2 * time.Second):
		case <-t.stopCh:
			return
		}
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

			var resp heartbeatResponse
			err := func() error {
				hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				return conn.Invoke(hbCtx, methodHeartbeat, &heartbeatRequest{
					AgentID: t.cfg.AgentID, Hostname: t.cfg.Hostname,
					Timestamp: time.Now().UnixNano(), OS: "linux",
					TaskResults: results,
				}, &resp, grpc.CallContentSubtype("json"))
			}()
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
