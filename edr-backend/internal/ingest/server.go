// internal/ingest/server.go
// gRPC server that receives events from EDR agents.
// Implements proto.EventServiceServer.

package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"

	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/models"
	pb "github.com/youredr/edr-backend/internal/proto"
	"github.com/youredr/edr-backend/internal/store"
)

// Server implements the gRPC EventService.
type Server struct {
	store    *store.Store
	engine   *detection.Engine
	log      zerolog.Logger
	grpc     *grpc.Server
	configVer string
}

// TLSConfig holds cert paths for the gRPC server.
type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CAFile   string // optional — for mutual TLS
}

// New creates an ingest Server.
func New(st *store.Store, eng *detection.Engine, log zerolog.Logger, tls TLSConfig) *Server {
	s := &Server{
		store:     st,
		engine:    eng,
		log:       log.With().Str("component", "ingest").Logger(),
		configVer: "1",
	}

	s.grpc = grpc.NewServer(
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
		grpc.MaxRecvMsgSize(8*1024*1024),  // 8 MB
		grpc.MaxSendMsgSize(1*1024*1024),  // 1 MB
		grpc.ChainUnaryInterceptor(loggingInterceptor(log)),
	)
	if tls.Enabled {
		creds, err := loadServerTLS(tls.CertFile, tls.KeyFile, tls.CAFile, log)
		if err != nil {
			log.Fatal().Err(err).Msg("load gRPC TLS credentials")
		}
		s.grpc = grpc.NewServer(
			grpc.Creds(creds),
			grpc.KeepaliveParams(keepalive.ServerParameters{
				MaxConnectionIdle: 5 * time.Minute, MaxConnectionAge: 2 * time.Hour,
				MaxConnectionAgeGrace: 30 * time.Second, Time: 30 * time.Second, Timeout: 10 * time.Second,
			}),
			grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
			grpc.MaxRecvMsgSize(8*1024*1024), grpc.MaxSendMsgSize(1*1024*1024),
			grpc.ChainUnaryInterceptor(loggingInterceptor(log)),
		)
		pb.RegisterEventServiceServer(s.grpc, s)
		log.Info().Str("cert", tls.CertFile).Msg("gRPC TLS enabled")
	}

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
		ConfigVer: s.configVer,
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
		ConfigVersion: s.configVer,
	}, nil
}

// StreamEvents receives a stream of events from an agent.
func (s *Server) StreamEvents(stream pb.EventService_StreamEventsServer) error {
	ctx := stream.Context()
	var agentID, hostname string
	received := 0

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
		ConfigVersion: s.configVer,
	}, nil
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (s *Server) processEvent(env *pb.EventEnvelope) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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

	// Store the event.
	if err := s.store.InsertEvent(ctx, ev); err != nil {
		s.log.Error().
			Err(err).
			Str("event_id", eventID).
			Msg("insert event failed")
		return
	}

	// Run detection rules against it.
	s.engine.Evaluate(ctx, ev)
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
