//go:build windows

// internal/monitor/network/monitor.go
// Network monitor for Windows.
//
// Primary path: ETW Microsoft-Windows-Kernel-Network provider.
// Delivers TCP+UDP, IPv4+IPv6 connection events in real time — fixes WIN-H2
// (original polling captured IPv4 TCP only, with a 3-second polling lag).
//
// Fallback: if the ETW session cannot be created (insufficient privilege or
// pre-Win10 build), the monitor transparently degrades to the original
// GetExtendedTcpTable polling approach (IPv4 TCP only, 3 s interval).

package network

import (
	"context"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/etw"
	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

type Config struct {
	IgnoreLocalhost bool
}

type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	sess   *etw.Session
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "network").Logger(),
	}
}

// Start registers the ETW Kernel-Network provider and begins consuming events.
// Falls back to GetExtendedTcpTable polling if the ETW session cannot be established.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	sess, err := etw.NewSession("TraceGuard-Net")
	if err != nil {
		m.log.Warn().Err(err).Msg("ETW session unavailable, falling back to polling")
		return m.startPolling(ctx)
	}

	// Verbose level; all keywords so we receive connect/disconnect/accept for all protocols.
	if err := sess.EnableProvider(etw.GUIDKernelNetwork, etw.TraceLevelVerbose, 0xFFFFFFFFFFFFFFFF); err != nil {
		sess.Close()
		m.log.Warn().Err(err).Msg("ETW provider enable failed, falling back to polling")
		return m.startPolling(ctx)
	}

	sess.Subscribe(etw.GUIDKernelNetwork, m.handleETWEvent)
	m.sess = sess

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := sess.Consume(ctx); err != nil && ctx.Err() == nil {
			m.log.Error().Err(err).Msg("ETW consume error")
		}
	}()

	m.log.Info().Msg("network monitor started (ETW Microsoft-Windows-Kernel-Network)")
	return nil
}

// Stop cancels the ETW session and waits for the dispatch goroutine to exit.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.sess != nil {
		m.sess.Close()
	}
	m.wg.Wait()
	m.log.Info().Msg("network monitor stopped")
}

// handleETWEvent dispatches Kernel-Network events to IPv4 or IPv6 handlers.
//
// See parse.go for the UserData byte layouts.
func (m *Monitor) handleETWEvent(ev etw.Event) {
	switch ev.EventID {
	case etw.EventTcpConnect:
		m.handleIPv4(ev, types.EventNetConnect, types.ProtoTCP, types.DirOutbound, types.ConnStateEstablished)
	case etw.EventTcpDisconnect:
		m.handleIPv4(ev, types.EventNetClose, types.ProtoTCP, "", types.ConnStateClosed)
	case etw.EventTcpAccept:
		m.handleIPv4(ev, types.EventNetAccept, types.ProtoTCP, types.DirInbound, types.ConnStateEstablished)
	case etw.EventUdpSend:
		m.handleIPv4(ev, types.EventNetConnect, types.ProtoUDP, types.DirOutbound, "")
	case etw.EventUdpReceive:
		m.handleIPv4(ev, types.EventNetConnect, types.ProtoUDP, types.DirInbound, "")
	case etw.EventTcpv6Connect:
		m.handleIPv6(ev, types.EventNetConnect, types.ProtoTCP, types.DirOutbound, types.ConnStateEstablished)
	case etw.EventTcpv6Disconnect:
		m.handleIPv6(ev, types.EventNetClose, types.ProtoTCP, "", types.ConnStateClosed)
	case etw.EventUdpv6Send:
		m.handleIPv6(ev, types.EventNetConnect, types.ProtoUDP, types.DirOutbound, "")
	case etw.EventUdpv6Receive:
		m.handleIPv6(ev, types.EventNetConnect, types.ProtoUDP, types.DirInbound, "")
	}
}

func (m *Monitor) handleIPv4(ev etw.Event, evType types.EventType, proto types.NetworkProtocol, dir types.NetworkDirection, state types.NetworkConnState) {
	parsed, ok := parseIPv4NetEvent(ev.UserData)
	if !ok {
		return
	}
	if m.cfg.IgnoreLocalhost && (isLoopback(parsed.DstIP) || isLoopback(parsed.SrcIP)) {
		return
	}
	pid := parsed.PID
	if pid == 0 {
		pid = ev.ProcessID
	}
	m.bus.Publish(&types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      evType,
			Timestamp: ev.Timestamp,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Process:   types.ProcessContext{PID: pid},
		},
		SrcIP:     parsed.SrcIP,
		SrcPort:   parsed.SrcPort,
		DstIP:     parsed.DstIP,
		DstPort:   parsed.DstPort,
		Protocol:  proto,
		Direction: dir,
		State:     state,
		IsPrivate: isPrivateIP(parsed.DstIP),
	})
}

func (m *Monitor) handleIPv6(ev etw.Event, evType types.EventType, proto types.NetworkProtocol, dir types.NetworkDirection, state types.NetworkConnState) {
	parsed, ok := parseIPv6NetEvent(ev.UserData)
	if !ok {
		return
	}
	if m.cfg.IgnoreLocalhost && (isLoopback(parsed.DstIP) || isLoopback(parsed.SrcIP)) {
		return
	}
	pid := parsed.PID
	if pid == 0 {
		pid = ev.ProcessID
	}
	m.bus.Publish(&types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      evType,
			Timestamp: ev.Timestamp,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Process:   types.ProcessContext{PID: pid},
		},
		SrcIP:     parsed.SrcIP,
		SrcPort:   parsed.SrcPort,
		DstIP:     parsed.DstIP,
		DstPort:   parsed.DstPort,
		Protocol:  proto,
		Direction: dir,
		State:     state,
		IsPrivate: isPrivateIPv6(parsed.DstIP),
	})
}

// ── Polling fallback ──────────────────────────────────────────────────────────
// Preserved verbatim from original implementation.
// Activated when the ETW session cannot be established.
// Covers IPv4 TCP established connections only (GetExtendedTcpTable limitation).

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("network monitor started (polling GetExtendedTcpTable)")
	return nil
}

// connKey uniquely identifies a TCP connection.
type connKey struct {
	LocalAddr  [4]byte
	LocalPort  uint16
	RemoteAddr [4]byte
	RemotePort uint16
	PID        uint32
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[connKey]bool)
	// Build initial baseline.
	for _, conn := range m.getTcpConnections() {
		known[conn.key()] = true
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.getTcpConnections()
			currentMap := make(map[connKey]bool)
			for _, conn := range current {
				k := conn.key()
				currentMap[k] = true
				if !known[k] {
					m.emitConnect(conn)
				}
			}
			// Detect closed connections.
			for k := range known {
				if !currentMap[k] {
					m.emitClose(k)
				}
			}
			known = currentMap
		}
	}
}

type tcpConn struct {
	State      uint32
	LocalAddr  [4]byte
	LocalPort  uint16
	RemoteAddr [4]byte
	RemotePort uint16
	PID        uint32
}

func (c *tcpConn) key() connKey {
	return connKey{
		LocalAddr: c.LocalAddr, LocalPort: c.LocalPort,
		RemoteAddr: c.RemoteAddr, RemotePort: c.RemotePort, PID: c.PID,
	}
}

func (m *Monitor) getTcpConnections() []tcpConn {
	var size uint32
	// First call to get buffer size.
	modIphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable := modIphlpapi.NewProc("GetExtendedTcpTable")

	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, windows.AF_INET, 5, 0) // TCP_TABLE_OWNER_PID_ALL=5
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, windows.AF_INET, 5, 0,
	)
	if ret != 0 {
		return nil
	}

	type MIB_TCPROW_OWNER_PID struct {
		State      uint32
		LocalAddr  [4]byte
		LocalPort  uint32
		RemoteAddr [4]byte
		RemotePort uint32
		PID        uint32
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	var result []tcpConn

	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		// Only track established connections.
		if row.State != 5 { // MIB_TCP_STATE_ESTAB = 5
			continue
		}

		localIP := net.IP(row.LocalAddr[:])
		remoteIP := net.IP(row.RemoteAddr[:])

		if m.cfg.IgnoreLocalhost && (localIP.IsLoopback() || remoteIP.IsLoopback()) {
			continue
		}

		result = append(result, tcpConn{
			State:      row.State,
			LocalAddr:  row.LocalAddr,
			LocalPort:  uint16(ntohs(row.LocalPort)),
			RemoteAddr: row.RemoteAddr,
			RemotePort: uint16(ntohs(row.RemotePort)),
			PID:        row.PID,
		})
	}

	return result
}

func (m *Monitor) emitConnect(conn tcpConn) {
	localIP := net.IP(conn.LocalAddr[:]).String()
	remoteIP := net.IP(conn.RemoteAddr[:]).String()

	ev := &types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID: uuid.New().String(), Type: types.EventNetConnect,
			Timestamp: time.Now(), AgentID: m.bus.AgentID(), Hostname: m.bus.Hostname(),
			Severity: types.SeverityInfo,
			Process:  types.ProcessContext{PID: conn.PID},
		},
		SrcIP: localIP, SrcPort: conn.LocalPort,
		DstIP: remoteIP, DstPort: conn.RemotePort,
		Protocol: types.ProtoTCP, Direction: types.DirOutbound,
		State:     types.ConnStateEstablished,
		IsPrivate: isPrivateIP(remoteIP),
	}
	m.bus.Publish(ev)
}

func (m *Monitor) emitClose(k connKey) {
	localIP := net.IP(k.LocalAddr[:]).String()
	remoteIP := net.IP(k.RemoteAddr[:]).String()

	ev := &types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID: uuid.New().String(), Type: types.EventNetClose,
			Timestamp: time.Now(), AgentID: m.bus.AgentID(), Hostname: m.bus.Hostname(),
			Severity: types.SeverityInfo,
			Process:  types.ProcessContext{PID: k.PID},
		},
		SrcIP: localIP, SrcPort: k.LocalPort,
		DstIP: remoteIP, DstPort: k.RemotePort,
		Protocol: types.ProtoTCP, State: types.ConnStateClosed,
	}
	m.bus.Publish(ev)
}

func ntohs(port uint32) uint32 {
	return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
