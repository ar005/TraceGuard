// internal/ingest/server.go
// gRPC server that receives events from EDR agents.
// Implements proto.EventServiceServer.

package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"

	"github.com/youredr/edr-backend/internal/configver"
	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/liveresponse"
	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/models"
	pb "github.com/youredr/edr-backend/internal/proto"
	"github.com/youredr/edr-backend/internal/sse"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	batchSize          = 50
	batchFlushInterval = 200 * time.Millisecond
)

// batchEntry pairs an event with its envelope for post-insert processing.
type batchEntry struct {
	event *models.Event
	env   *pb.EventEnvelope
}

// Server implements the gRPC EventService.
type Server struct {
	store     *store.Store
	engine    *detection.Engine
	sseBroker *sse.Broker
	lr        *liveresponse.Manager
	log       zerolog.Logger
	grpc      *grpc.Server

	batchMu    sync.Mutex
	batchBuf   []*batchEntry
	batchTimer *time.Timer
}

// TLSConfig holds cert paths for the gRPC server.
type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CAFile   string // optional — for mutual TLS
}

// New creates an ingest Server.
func New(st *store.Store, eng *detection.Engine, sb *sse.Broker, lr *liveresponse.Manager, log zerolog.Logger, tls TLSConfig) *Server {
	s := &Server{
		store:     st,
		engine:    eng,
		sseBroker: sb,
		lr:        lr,
		log:       log.With().Str("component", "ingest").Logger(),
	}

	// Build common gRPC server options.
	commonOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      2 * time.Hour,
			MaxConnectionAgeGrace: 30 * time.Second,
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxRecvMsgSize(8 * 1024 * 1024), // 8 MB
		grpc.MaxSendMsgSize(1 * 1024 * 1024), // 1 MB
		grpc.ChainUnaryInterceptor(loggingInterceptor(log)),
	}
	if tls.Enabled {
		creds, err := loadServerTLS(tls.CertFile, tls.KeyFile, tls.CAFile, log)
		if err != nil {
			log.Fatal().Err(err).Msg("load gRPC TLS credentials")
		}
		commonOpts = append([]grpc.ServerOption{grpc.Creds(creds)}, commonOpts...)
		log.Info().Str("cert", tls.CertFile).Msg("gRPC TLS enabled")
	}
	s.grpc = grpc.NewServer(commonOpts...)
	pb.RegisterEventServiceServer(s.grpc, s)
	return s
}

// Listen starts the gRPC listener on addr (e.g. ":50051").
func (s *Server) Listen(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.log.Info().Str("addr", addr).Msg("gRPC ingest server listening")
	return s.grpc.Serve(lis)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	s.grpc.GracefulStop()
}

// ─── EventServiceServer implementation ───────────────────────────────────────

// Register is called when an agent starts and registers with the backend.
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	ip := peerIP(ctx)
	if req.IP == "" {
		req.IP = ip
	}

	agent := &models.Agent{
		ID:        req.AgentID,
		Hostname:  req.Hostname,
		OS:        req.OS,
		OSVersion: req.OSVersion,
		IP:        req.IP,
		AgentVer:  req.AgentVer,
		ConfigVer: configver.Get(),
		Tags:      req.Tags,
		Env:       req.Env,
		Notes:     req.Notes,
	}

	if err := s.store.UpsertAgent(ctx, agent); err != nil {
		s.log.Error().Err(err).Str("agent_id", req.AgentID).Msg("upsert agent failed")
		return &pb.RegisterResponse{Ok: false}, err
	}

	s.log.Info().
		Str("agent_id", req.AgentID).
		Str("hostname", req.Hostname).
		Str("os",       req.OS).
		Str("ip",       req.IP).
		Msg("agent registered")

	return &pb.RegisterResponse{
		Ok:            true,
		AssignedID:    req.AgentID,
		ConfigVersion: configver.Get(),
	}, nil
}

// StreamEvents receives a stream of events from an agent.
func (s *Server) StreamEvents(stream pb.EventService_StreamEventsServer) error {
	ctx := stream.Context()
	var agentID, hostname string
	received := 0

	metrics.GRPCStreamsActive.Inc()
	defer metrics.GRPCStreamsActive.Dec()

	for {
		select {
		case <-ctx.Done():
			s.log.Info().
				Str("agent", hostname).
				Int("received", received).
				Msg("stream closed by client")
			if agentID != "" {
				_ = s.store.MarkAgentOffline(context.Background(), agentID)
			}
			return nil
		default:
		}

		env, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if agentID != "" {
				_ = s.store.MarkAgentOffline(context.Background(), agentID)
			}
			return err
		}

		agentID = env.AgentID
		hostname = env.Hostname
		received++

		metrics.EventsReceived.WithLabelValues(env.EventType, env.AgentID).Inc()

		// Process event asynchronously to keep stream responsive.
		go s.processEvent(env)
	}

	return stream.SendAndClose(&pb.StreamResponse{
		Ok:      true,
		Message: "stream closed",
	})
}

// Heartbeat handles periodic keepalive from agents.
func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	metrics.HeartbeatsReceived.Inc()

	if err := s.store.TouchAgent(ctx, req.AgentID); err != nil {
		// Non-fatal: agent might not be registered yet.
		s.log.Warn().Str("agent_id", req.AgentID).Err(err).Msg("heartbeat touch failed")
	}

	s.log.Debug().
		Str("agent_id", req.AgentID).
		Str("hostname", req.Hostname).
		Msg("heartbeat")

	return &pb.HeartbeatResponse{
		Ok:            true,
		ServerTime:    time.Now().UnixNano(),
		ConfigVersion: configver.Get(),
	}, nil
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (s *Server) processEvent(env *pb.EventEnvelope) {
	// Validate payload is valid JSON.
	if !json.Valid(env.Payload) {
		s.log.Warn().
			Str("agent",      env.AgentID).
			Str("event_type", env.EventType).
			Msg("invalid JSON payload — dropping event")
		return
	}

	// Ensure event has an ID.
	eventID := env.EventID
	if eventID == "" {
		eventID = "evt-" + uuid.New().String()
	}

	ts := time.Unix(0, env.Timestamp)
	if ts.IsZero() || ts.Before(time.Now().Add(-24*time.Hour)) {
		ts = time.Now()
	}

	ev := &models.Event{
		ID:        eventID,
		AgentID:   env.AgentID,
		Hostname:  env.Hostname,
		EventType: env.EventType,
		Timestamp: ts,
		Payload:   json.RawMessage(env.Payload),
	}

	// Add to batch instead of inserting immediately.
	s.addToBatch(&batchEntry{event: ev, env: env})
}

func (s *Server) addToBatch(entry *batchEntry) {
	s.batchMu.Lock()
	s.batchBuf = append(s.batchBuf, entry)

	// Flush if batch is full.
	if len(s.batchBuf) >= batchSize {
		batch := s.batchBuf
		s.batchBuf = nil
		if s.batchTimer != nil {
			s.batchTimer.Stop()
		}
		s.batchMu.Unlock()
		s.flushBatch(batch)
		return
	}

	// Start/reset flush timer for partial batches.
	if s.batchTimer != nil {
		s.batchTimer.Stop()
	}
	s.batchTimer = time.AfterFunc(batchFlushInterval, func() {
		s.batchMu.Lock()
		batch := s.batchBuf
		s.batchBuf = nil
		s.batchMu.Unlock()
		if len(batch) > 0 {
			s.flushBatch(batch)
		}
	})
	s.batchMu.Unlock()
}

func (s *Server) flushBatch(batch []*batchEntry) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Batch insert all events.
	events := make([]*models.Event, len(batch))
	for i, b := range batch {
		events[i] = b.event
	}

	if err := s.store.InsertEventBatch(ctx, events); err != nil {
		s.log.Error().Err(err).Int("batch_size", len(batch)).Msg("batch insert failed")
		metrics.EventsDropped.Add(float64(len(batch)))
		return
	}
	metrics.EventsStored.Add(float64(len(batch)))

	// Post-insert processing for each event (SSE, detection, PKG_INVENTORY).
	for _, b := range batch {
		if s.sseBroker != nil {
			go s.sseBroker.Publish(b.event)
		}

		detStart := time.Now()
		s.engine.Evaluate(ctx, b.event)
		metrics.DetectionDuration.Observe(time.Since(detStart).Seconds())

		if b.env.EventType == "PKG_INVENTORY" {
			go s.processPackageInventory(ctx, b.env.AgentID, b.env.Payload)
		}
	}
}

func (s *Server) processPackageInventory(ctx context.Context, agentID string, payload []byte) {
	var data struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Arch    string `json:"arch"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		s.log.Error().Err(err).Msg("failed to parse PKG_INVENTORY payload")
		return
	}
	if len(data.Packages) == 0 {
		return
	}

	pkgs := make([]models.AgentPackage, len(data.Packages))
	for i, p := range data.Packages {
		pkgs[i] = models.AgentPackage{Name: p.Name, Version: p.Version, Arch: p.Arch}
	}

	if err := s.store.UpsertAgentPackages(ctx, agentID, pkgs); err != nil {
		s.log.Error().Err(err).Str("agent", agentID).Int("packages", len(pkgs)).Msg("failed to store packages")
		return
	}
	s.log.Info().Str("agent", agentID).Int("packages", len(pkgs)).Msg("package inventory updated")
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func loggingInterceptor(log zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		log.Debug().
			Str("method",  info.FullMethod).
			Dur("latency", time.Since(start)).
			Err(err).
			Msg("grpc unary")
		return resp, err
	}
}

func peerIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if addr, ok := p.Addr.(*net.TCPAddr); ok {
			return addr.IP.String()
		}
		return p.Addr.String()
	}
	return ""
}

// loadServerTLS builds gRPC server credentials from PEM files.
// caFile is optional; when set it enables mutual TLS (client cert required).
func loadServerTLS(certFile, keyFile, caFile string, log zerolog.Logger) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.ClientCAs  = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Info().Str("ca", caFile).Msg("mutual TLS: client cert required")
	}
	return credentials.NewTLS(tlsCfg), nil
}

// LiveResponse implements the bidirectional live response stream.
// The agent connects, registers, then listens for commands and sends results.
func (s *Server) LiveResponse(stream pb.EventService_LiveResponseServer) error {
	// First message from agent must be a result with status="register" containing agent_id.
	initMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("live response init recv: %w", err)
	}
	agentID := initMsg.AgentID
	if agentID == "" {
		return fmt.Errorf("live response: agent_id required in initial message")
	}

	s.log.Info().Str("agent_id", agentID).Msg("live response session started")

	cmdCh := s.lr.RegisterAgent(agentID)
	defer s.lr.UnregisterAgent(agentID)

	// Read results from agent in background.
	errCh := make(chan error, 1)
	go func() {
		for {
			result, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			s.lr.DeliverResult(agentID, liveresponse.Result{
				CommandID: result.CommandID,
				AgentID:   result.AgentID,
				Status:    result.Status,
				ExitCode:  result.ExitCode,
				Stdout:    result.Stdout,
				Stderr:    result.Stderr,
				Error:     result.Error,
			})
		}
	}()

	// Send commands to agent from the session channel.
	for {
		select {
		case cmd, ok := <-cmdCh:
			if !ok {
				return nil // session closed
			}
			if err := stream.Send(&pb.LiveCommand{
				CommandID: cmd.ID,
				Action:    cmd.Action,
				Args:      cmd.Args,
				Timeout:   cmd.Timeout,
			}); err != nil {
				return fmt.Errorf("send command: %w", err)
			}
		case err := <-errCh:
			if err == io.EOF {
				s.log.Info().Str("agent_id", agentID).Msg("live response stream closed by agent")
				return nil
			}
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// LRManager returns the live response manager for use by the REST API.
func (s *Server) LRManager() *liveresponse.Manager {
	return s.lr
}
