// internal/proto/edr.go
// Hand-written gRPC service definitions matching proto/edr.proto.
// In production: run `protoc --go_out=. --go-grpc_out=. proto/edr.proto`
// and replace this file with the generated output.

package proto

import (
	"context"

	"google.golang.org/grpc"
)

// ─── Message types ────────────────────────────────────────────────────────────

type EventEnvelope struct {
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Timestamp int64  `json:"timestamp"`
	Payload   []byte `json:"payload"`
	OS        string `json:"os"`
	AgentVer  string `json:"agent_ver"`
}

type HeartbeatRequest struct {
	AgentID  string      `json:"agent_id"`
	Hostname string      `json:"hostname"`
	Timestamp int64      `json:"timestamp"`
	AgentVer string      `json:"agent_ver"`
	OS       string      `json:"os"`
	Stats    *AgentStats `json:"stats,omitempty"`
}

type AgentStats struct {
	EventsSent    uint64  `json:"events_sent"`
	EventsDropped uint64  `json:"events_dropped"`
	BufferSize    uint64  `json:"buffer_size"`
	CPUPct        float32 `json:"cpu_pct"`
	MemBytes      uint64  `json:"mem_bytes"`
}

type HeartbeatResponse struct {
	Ok            bool   `json:"ok"`
	ServerTime    int64  `json:"server_time"`
	ConfigVersion string `json:"config_version"`
}

type StreamResponse struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
}

type RegisterRequest struct {
	AgentID   string   `json:"agent_id"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	OSVersion string   `json:"os_version"`
	AgentVer  string   `json:"agent_ver"`
	IP        string   `json:"ip"`
	Tags      []string `json:"tags"`
	Env       string   `json:"env"`
	Notes     string   `json:"notes"`
}

type RegisterResponse struct {
	Ok            bool   `json:"ok"`
	AssignedID    string `json:"assigned_id"`
	ConfigVersion string `json:"config_version"`
}

// ─── Live Response message types ─────────────────────────────────────────────

// LiveCommand is sent from backend to agent.
type LiveCommand struct {
	CommandID string   `json:"command_id"` // UUID for tracking
	Action    string   `json:"action"`     // exec, kill, ls, cat, upload, download, netstat, ps
	Args      []string `json:"args"`       // command arguments
	Timeout   int      `json:"timeout"`    // seconds (0 = default 30s)
}

// LiveResult is sent from agent back to backend.
type LiveResult struct {
	CommandID string `json:"command_id"`
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`  // running, completed, error, timeout
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Error     string `json:"error,omitempty"`
}

// ─── Service interfaces ───────────────────────────────────────────────────────

// EventServiceServer is the server-side interface (implement this).
type EventServiceServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	StreamEvents(EventService_StreamEventsServer) error
	Heartbeat(context.Context, *HeartbeatRequest) (*HeartbeatResponse, error)
	LiveResponse(EventService_LiveResponseServer) error
}

// EventService_LiveResponseServer is the server-side bidi stream interface.
type EventService_LiveResponseServer interface {
	Send(*LiveCommand) error
	Recv() (*LiveResult, error)
	grpc.ServerStream
}

// EventService_StreamEventsServer is the server-side streaming interface.
type EventService_StreamEventsServer interface {
	Recv() (*EventEnvelope, error)
	SendAndClose(*StreamResponse) error
	grpc.ServerStream
}

// EventServiceClient is the client-side interface (agent uses this).
type EventServiceClient interface {
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	StreamEvents(ctx context.Context, opts ...grpc.CallOption) (EventService_StreamEventsClient, error)
	Heartbeat(ctx context.Context, in *HeartbeatRequest, opts ...grpc.CallOption) (*HeartbeatResponse, error)
}

// EventService_StreamEventsClient is the client-side streaming interface.
type EventService_StreamEventsClient interface {
	Send(*EventEnvelope) error
	CloseAndRecv() (*StreamResponse, error)
	grpc.ClientStream
}

// ─── Service descriptor (for gRPC registration) ───────────────────────────────

const EventService_Register_FullMethodName      = "/edr.v1.EventService/Register"
const EventService_StreamEvents_FullMethodName  = "/edr.v1.EventService/StreamEvents"
const EventService_Heartbeat_FullMethodName     = "/edr.v1.EventService/Heartbeat"
const EventService_LiveResponse_FullMethodName  = "/edr.v1.EventService/LiveResponse"

// ServiceDesc is the gRPC service descriptor for EventService.
var EventService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "edr.v1.EventService",
	HandlerType: (*EventServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Register",
			Handler:    _EventService_Register_Handler,
		},
		{
			MethodName: "Heartbeat",
			Handler:    _EventService_Heartbeat_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamEvents",
			Handler:       _EventService_StreamEvents_Handler,
			ClientStreams:  true,
		},
		{
			StreamName:    "LiveResponse",
			Handler:       _EventService_LiveResponse_Handler,
			ServerStreams:  true,
			ClientStreams:  true,
		},
	},
	Metadata: "edr.proto",
}

// ─── Handler shims ────────────────────────────────────────────────────────────

func _EventService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EventServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: EventService_Register_FullMethodName}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EventServiceServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EventService_Heartbeat_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HeartbeatRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EventServiceServer).Heartbeat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: EventService_Heartbeat_FullMethodName}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EventServiceServer).Heartbeat(ctx, req.(*HeartbeatRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EventService_StreamEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(EventServiceServer).StreamEvents(&eventServiceStreamEventsServer{stream})
}

// ─── Stream wrappers ─────────────────────────────────────────────────────────

type eventServiceStreamEventsServer struct {
	grpc.ServerStream
}

func (x *eventServiceStreamEventsServer) SendAndClose(m *StreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *eventServiceStreamEventsServer) Recv() (*EventEnvelope, error) {
	m := new(EventEnvelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _EventService_LiveResponse_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(EventServiceServer).LiveResponse(&eventServiceLiveResponseServer{stream})
}

type eventServiceLiveResponseServer struct {
	grpc.ServerStream
}

func (x *eventServiceLiveResponseServer) Send(m *LiveCommand) error {
	return x.ServerStream.SendMsg(m)
}

func (x *eventServiceLiveResponseServer) Recv() (*LiveResult, error) {
	m := new(LiveResult)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// RegisterEventServiceServer registers the server implementation.
func RegisterEventServiceServer(s *grpc.Server, srv EventServiceServer) {
	s.RegisterService(&EventService_ServiceDesc, srv)
}
