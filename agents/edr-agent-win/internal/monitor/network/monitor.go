// internal/monitor/network/monitor.go
// Network monitor for Windows — polls GetExtendedTcpTable for connection changes.
// Future: ETW Microsoft-Windows-Kernel-Network for real-time events.

package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

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

func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	return nil
}

func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
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
		State: types.ConnStateEstablished,
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

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf // suppress unused import
