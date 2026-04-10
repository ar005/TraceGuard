// Package tlssni passively extracts TLS SNI (Server Name Indication) from
// ClientHello messages using a raw AF_INET socket. This reveals which HTTPS
// domains every process connects to without any certificates or MITM proxy.
//
// Requires root or CAP_NET_RAW. The agent already runs as root for eBPF.

package tlssni

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config for the TLS SNI monitor.
type Config struct {
	Enabled bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{Enabled: true}
}

// Monitor captures TLS ClientHello packets and extracts SNI fields.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a new TLS SNI monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "tlssni").Logger(),
		stopCh: make(chan struct{}),
	}
}

// ethHeaderLen is the size of the Ethernet header (SOCK_RAW includes it).
const ethHeaderLen = 14

// Start opens a raw AF_PACKET/SOCK_RAW socket and begins capturing TLS ClientHello packets.
// SOCK_RAW captures both incoming AND outgoing packets including Ethernet header.
func (m *Monitor) Start(ctx context.Context) error {
	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, proto)
	if err != nil {
		return fmt.Errorf("AF_PACKET socket: %w (need root/CAP_NET_RAW)", err)
	}

	// Set receive timeout so we can check for cancellation periodically.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	m.wg.Add(1)
	go m.readLoop(ctx, fd)

	m.log.Info().Msg("TLS SNI monitor started (AF_PACKET SOCK_RAW)")
	return nil
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}

// Stop gracefully shuts down the monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.log.Info().Msg("TLS SNI monitor stopped")
}

// readLoop reads raw TCP packets and extracts SNI from TLS ClientHello messages.
func (m *Monitor) readLoop(ctx context.Context, fd int) {
	defer m.wg.Done()
	defer unix.Close(fd)

	buf := make([]byte, 65535)
	seen := make(map[string]time.Time) // dedup: "domain:srcPort" -> time
	lastClean := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// Timeout is expected — lets us check ctx/stopCh.
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			// Transient errors — keep going.
			m.log.Debug().Err(err).Msg("recvfrom error")
			continue
		}
		if n < ethHeaderLen+40 {
			continue // too short for Ethernet + IP + TCP headers
		}

		// ── Check EtherType is IPv4 (0x0800) ─────────────────────────
		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType != 0x0800 {
			continue
		}

		// ── Parse IP header (after 14-byte Ethernet header) ──────────
		ip := buf[ethHeaderLen:]
		ipVer := ip[0] >> 4
		if ipVer != 4 {
			continue
		}
		ipProto := ip[9]
		if ipProto != 6 {
			continue // TCP only
		}
		ipHeaderLen := int(ip[0]&0x0f) * 4
		if n < ethHeaderLen+ipHeaderLen+20 {
			continue
		}

		srcIP := net.IPv4(ip[12], ip[13], ip[14], ip[15]).String()
		dstIP := net.IPv4(ip[16], ip[17], ip[18], ip[19]).String()

		// ── Parse TCP header ─────────────────────────────────────────
		tcp := ip[ipHeaderLen:]
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		tcpHeaderLen := int(tcp[12]>>4) * 4

		// Only interested in outbound connections to port 443.
		if dstPort != 443 {
			continue
		}

		// ── Get TCP payload ──────────────────────────────────────────
		payloadOffset := ethHeaderLen + ipHeaderLen + tcpHeaderLen
		if payloadOffset >= n {
			continue
		}
		payload := buf[payloadOffset:n]
		if len(payload) < 6 {
			continue
		}

		// ── Parse TLS ClientHello ────────────────────────────────────
		sni, tlsVersion := parseTLSClientHello(payload)
		if sni == "" {
			continue
		}

		// ── Dedup ────────────────────────────────────────────────────
		key := fmt.Sprintf("%s:%d", sni, srcPort)
		if t, ok := seen[key]; ok && time.Since(t) < 30*time.Second {
			continue
		}
		seen[key] = time.Now()

		// Periodic cleanup of dedup cache.
		if time.Since(lastClean) > 60*time.Second || len(seen) > 10000 {
			now := time.Now()
			for k, t := range seen {
				if now.Sub(t) > 60*time.Second {
					delete(seen, k)
				}
			}
			lastClean = now
		}

		// ── Resolve PID from /proc/net/tcp ───────────────────────────
		pid, comm := lookupPIDByPort(srcPort)

		// ── Emit event ───────────────────────────────────────────────
		ev := &types.TLSSNIEvent{
			BaseEvent: types.BaseEvent{
				ID:        uuid.New().String(),
				Type:      types.EventTLSSNI,
				Timestamp: time.Now(),
				AgentID:   m.bus.AgentID(),
				Hostname:  m.bus.Hostname(),
				Severity:  types.SeverityInfo,
			},
			Domain:      sni,
			DstIP:       dstIP,
			DstPort:     dstPort,
			SrcIP:       srcIP,
			SrcPort:     srcPort,
			TLSVersion:  tlsVersion,
			ProcessPID:  pid,
			ProcessComm: comm,
		}

		m.bus.Publish(ev)
		m.log.Debug().
			Str("domain", sni).
			Str("dst", dstIP).
			Uint32("pid", pid).
			Str("comm", comm).
			Str("tls", tlsVersion).
			Msg("TLS SNI captured")
	}
}

// parseTLSClientHello extracts the SNI server_name and TLS version from a
// TLS ClientHello record. Returns empty strings if the data is not a valid
// ClientHello or does not contain an SNI extension.
func parseTLSClientHello(data []byte) (sni string, tlsVersion string) {
	if len(data) < 6 {
		return
	}
	// Content type 0x16 = Handshake.
	if data[0] != 0x16 {
		return
	}

	// TLS version from record header.
	major, minor := data[1], data[2]
	switch {
	case major == 3 && minor == 0:
		tlsVersion = "SSL 3.0"
	case major == 3 && minor == 1:
		tlsVersion = "TLS 1.0"
	case major == 3 && minor == 2:
		tlsVersion = "TLS 1.1"
	case major == 3 && minor == 3:
		tlsVersion = "TLS 1.2"
	case major == 3 && minor == 4:
		tlsVersion = "TLS 1.3"
	default:
		tlsVersion = fmt.Sprintf("TLS %d.%d", major, minor)
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return
	}

	// Handshake message starts at byte 5.
	hs := data[5 : 5+recordLen]
	if len(hs) < 1 || hs[0] != 0x01 {
		return // not ClientHello
	}

	// Skip: handshake type (1) + handshake length (3) + client version (2) + random (32).
	offset := 1 + 3 + 2 + 32
	if len(hs) < offset+1 {
		return
	}

	// Session ID (1-byte length prefix).
	sessionIDLen := int(hs[offset])
	offset += 1 + sessionIDLen
	if len(hs) < offset+2 {
		return
	}

	// Cipher suites (2-byte length prefix).
	cipherLen := int(binary.BigEndian.Uint16(hs[offset:]))
	offset += 2 + cipherLen
	if len(hs) < offset+1 {
		return
	}

	// Compression methods (1-byte length prefix).
	compLen := int(hs[offset])
	offset += 1 + compLen
	if len(hs) < offset+2 {
		return
	}

	// Extensions (2-byte length prefix).
	extLen := int(binary.BigEndian.Uint16(hs[offset:]))
	offset += 2
	extEnd := offset + extLen
	if len(hs) < extEnd {
		return
	}

	// Walk extensions looking for SNI (type 0x0000).
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[offset:])
		extDataLen := int(binary.BigEndian.Uint16(hs[offset+2:]))
		offset += 4
		if offset+extDataLen > extEnd {
			break
		}

		if extType == 0x0000 { // SNI extension
			sniData := hs[offset : offset+extDataLen]
			if len(sniData) < 5 {
				break
			}
			// Skip SNI list length (2 bytes), then read first entry.
			nameType := sniData[2]
			nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
			if nameType == 0 && len(sniData) >= 5+nameLen { // host_name type
				sni = string(sniData[5 : 5+nameLen])
			}
			break
		}
		offset += extDataLen
	}
	return
}

// lookupPIDByPort attempts to find the PID that owns the given local TCP port
// by reading /proc/net/tcp and scanning /proc/[pid]/fd for matching socket inodes.
func lookupPIDByPort(localPort uint16) (uint32, string) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0, ""
	}
	defer f.Close()

	portHex := fmt.Sprintf("%04X", localPort)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	var targetInode string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		// local_address is field[1] = "HEXIP:HEXPORT"
		parts := strings.Split(fields[1], ":")
		if len(parts) == 2 && strings.ToUpper(parts[1]) == portHex {
			targetInode = fields[9]
			break
		}
	}
	if targetInode == "" || targetInode == "0" {
		return 0, ""
	}

	// Scan /proc/[pid]/fd for the socket inode.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, ""
	}
	socketLink := "socket:[" + targetInode + "]"

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == socketLink {
				commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				comm := strings.TrimSpace(string(commBytes))
				return uint32(pid), comm
			}
		}
	}
	return 0, ""
}
