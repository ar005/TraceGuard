//go:build windows

// internal/monitor/tlssni/monitor.go
// TLS SNI monitor — captures TLS ClientHello packets via SIO_RCVALL raw sockets.
//
// For each non-loopback IPv4 interface: create an AF_INET SOCK_RAW socket,
// bind it to the interface address, enable SIO_RCVALL (promiscuous IP capture),
// and read raw IP packets.  Each packet is filtered to TCP/443 outbound traffic,
// parsed for a TLS ClientHello, and the SNI hostname is extracted and emitted.
//
// No Npcap, no gopacket, no CGO.  Requires SeNetworkAdminPrivilege (held by
// SYSTEM/Administrator).  If SIO_RCVALL fails on all interfaces (non-admin
// context), Start logs at Debug level and returns nil — the agent continues
// without TLS SNI visibility.
//
// PID is not available from raw sockets at the IP layer.  Events carry
// Tags: ["tls-sni","no-pid"] and ProcessPID: 0 so analysts know the field is absent.

package tlssni

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

const (
	// sioRcvall is the Windows ioctl that enables receipt of all IP packets
	// on a bound raw socket (equivalent of promiscuous mode at the IP layer).
	// Value: _WSAIOW(IOC_VENDOR, 1) = 0x80000000|0x18000000|0x00000001
	sioRcvall = uint32(0x98000001)
	rcvallOn  = uint32(1)

	// tlsPort is the well-known port for HTTPS / TLS.
	tlsPort = uint16(443)
)

// Config for the TLS SNI monitor.
type Config struct{}

// Monitor captures TLS SNI hostnames from outbound TCP/443 traffic on all
// non-loopback IPv4 interfaces using SIO_RCVALL raw sockets.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	socks  []syscall.Handle
	dedup  deduper
	mu     sync.Mutex // protects socks during Stop
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a TLS SNI monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg:   cfg,
		bus:   bus,
		log:   log.With().Str("monitor", "tlssni").Logger(),
		dedup: newDeduper(),
	}
}

// Start opens one raw socket per non-loopback IPv4 interface and begins
// capturing TLS ClientHello packets. Returns nil without emitting if no
// interface accepts SIO_RCVALL (non-admin context).
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	ifaces, err := net.Interfaces()
	if err != nil {
		m.log.Debug().Err(err).Msg("TLS SNI: failed to enumerate interfaces")
		return nil
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip4 := extractIPv4(addr)
			if ip4 == nil {
				continue
			}
			var localAddr [4]byte
			copy(localAddr[:], ip4)
			sock, err := m.openRawSocket(localAddr)
			if err != nil {
				m.log.Debug().Err(err).
					Str("iface", iface.Name).
					Str("addr", ip4.String()).
					Msg("TLS SNI: SIO_RCVALL failed on interface (requires admin)")
				continue
			}
			m.mu.Lock()
			m.socks = append(m.socks, sock)
			m.mu.Unlock()
			m.wg.Add(1)
			go m.readLoop(ctx, sock)
		}
	}

	if len(m.socks) == 0 {
		m.log.Debug().Msg("TLS SNI: no interfaces available for raw socket capture — monitor inactive")
		return nil
	}

	m.log.Info().Int("interfaces", len(m.socks)).Msg("TLS SNI monitor started (SIO_RCVALL)")
	return nil
}

// Stop closes all raw sockets and waits for capture goroutines to exit.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	// Closing the sockets unblocks any Recvfrom calls.
	m.mu.Lock()
	for _, sock := range m.socks {
		syscall.Closesocket(sock)
	}
	m.mu.Unlock()
	m.wg.Wait()
	m.log.Info().Msg("TLS SNI monitor stopped")
}

// openRawSocket creates an AF_INET SOCK_RAW socket bound to localAddr with
// SIO_RCVALL enabled to receive all incoming IP packets on that interface.
func (m *Monitor) openRawSocket(localAddr [4]byte) (syscall.Handle, error) {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return 0, fmt.Errorf("socket: %w", err)
	}

	sa := &syscall.SockaddrInet4{Addr: localAddr}
	if err := syscall.Bind(sock, sa); err != nil {
		syscall.Closesocket(sock)
		return 0, fmt.Errorf("bind %v: %w", localAddr, err)
	}

	// Enable SIO_RCVALL so the socket receives all IP packets on this interface,
	// not just packets addressed to localAddr.
	mode := rcvallOn
	var out uint32
	var bytesReturned uint32
	if err := windows.WSAIoctl(
		windows.Handle(sock),
		sioRcvall,
		(*byte)(unsafe.Pointer(&mode)),
		uint32(unsafe.Sizeof(mode)),
		(*byte)(unsafe.Pointer(&out)),
		uint32(unsafe.Sizeof(out)),
		&bytesReturned,
		nil,
		0,
	); err != nil {
		syscall.Closesocket(sock)
		return 0, fmt.Errorf("SIO_RCVALL: %w", err)
	}

	return sock, nil
}

// readLoop reads raw IP packets from sock until ctx is cancelled or the socket
// is closed. It filters to outbound TCP/443 and hands matching payloads to
// parsePacket.
func (m *Monitor) readLoop(ctx context.Context, sock syscall.Handle) {
	defer m.wg.Done()

	buf := make([]byte, 65536)
	for {
		// Best-effort early exit check before blocking.
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			// Closesocket from Stop() unblocks Recvfrom with an error.
			if ctx.Err() != nil {
				return
			}
			m.log.Debug().Err(err).Msg("TLS SNI: recvfrom error")
			return
		}
		if n > 0 {
			m.parsePacket(buf[:n])
		}
	}
}

// parsePacket processes a raw IP packet, looking for outbound TCP/443 packets
// that contain a TLS ClientHello.
func (m *Monitor) parsePacket(pkt []byte) {
	if len(pkt) < 20 {
		return
	}

	// IP header: version+IHL in first byte; IHL in lower 4 bits (units: 32-bit words).
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return
	}
	if pkt[9] != 6 { // protocol must be TCP
		return
	}

	srcIP := net.IP(pkt[12:16]).String()
	dstIP := net.IP(pkt[16:20]).String()

	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return
	}

	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	if dstPort != tlsPort {
		return
	}

	// TCP data offset: upper 4 bits of byte 12, in 32-bit word units.
	tcpDataOff := int(tcp[12]>>4) * 4
	if tcpDataOff < 20 || len(tcp) < tcpDataOff {
		return
	}

	payload := tcp[tcpDataOff:]
	if len(payload) == 0 {
		return
	}

	sni, tlsVer := parseTLSClientHelloSNI(payload)
	if sni == "" {
		return
	}

	// Dedup by source IP + SNI; PID is unavailable from raw sockets.
	key := srcIP + "|" + sni
	if m.dedup.seen(key) {
		return
	}

	m.bus.Publish(&types.TLSSNIEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventTLSSNI,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Tags:      []string{"tls-sni", "no-pid"},
		},
		Domain:  sni,
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		TLSVersion: tlsVer,
	})

	m.log.Info().
		Str("sni", sni).
		Str("src", fmt.Sprintf("%s:%d", srcIP, srcPort)).
		Str("dst", dstIP).
		Str("tls_ver", tlsVer).
		Msg("TLS SNI captured")
}

// extractIPv4 returns the IPv4 address from a net.Addr, or nil.
func extractIPv4(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPNet:
		return a.IP.To4()
	case *net.IPAddr:
		return a.IP.To4()
	}
	return nil
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
