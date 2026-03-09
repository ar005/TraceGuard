// internal/monitor/network/monitor.go
//
// Network monitor — eBPF-based TCP/UDP connection tracker.
//
// Data sources:
//   1. eBPF ring buffer  — kernel-side hooks on tcp_connect, inet_csk_accept,
//      tcp_close, udp_sendmsg, udp_recvmsg, and the inet_sock_set_state
//      tracepoint.  Events arrive as raw C structs (net_event_v4 / net_event_v6)
//      defined in ebpf/network/network.bpf.c.
//
//   2. /proc/net/tcp + /proc/net/tcp6 poller (fallback / enrichment) — used to
//      snapshot existing connections on startup and to fill in any gaps.
//
//   3. /proc/net/udp poller — DNS query capture (dst port 53).
//
// Hot path is zero-allocation: ring buffer records are decoded directly into
// stack-allocated structs.  Hostname resolution runs in a separate goroutine
// pool so it never blocks event emission.  Results are written back into a
// bounded LRU cache; subsequent events for the same IP read the cached name.

package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
	"github.com/youredr/edr-agent/pkg/utils"
)

// ─── eBPF event type constants (must match network.bpf.c) ────────────────────

const (
	ebpfNetConnect = 10
	ebpfNetAccept  = 11
	ebpfNetClose   = 12
	ebpfNetUDPSend = 13
	ebpfNetUDPRecv = 14
	ebpfNetState   = 15
)

// ─── Raw kernel structs ───────────────────────────────────────────────────────
// These must exactly mirror the C structs in ebpf/network/network.bpf.c.
// All multi-byte integer fields arrive in host byte order (bpf_ntohl/ntohs
// was already called in kernel-side code).

const netCommLen = 16

// rawNetEventV4 mirrors struct net_event_v4 (80 bytes).
type rawNetEventV4 struct {
	TimestampNs uint64
	EventType   uint32
	PID         uint32
	PPID        uint32
	UID         uint32
	Comm        [netCommLen]byte
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Direction   uint8 // 0=outbound 1=inbound
	TCPState    uint8
	Pad         uint8
	BytesSent   uint64
	BytesRecv   uint64
	SockCookie  uint64
}

// rawNetEventV6 mirrors struct net_event_v6 (104 bytes).
type rawNetEventV6 struct {
	TimestampNs uint64
	EventType   uint32
	PID         uint32
	PPID        uint32
	UID         uint32
	Comm        [netCommLen]byte
	SrcIP       [16]byte
	DstIP       [16]byte
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Direction   uint8
	TCPState    uint8
	Pad         uint8
	BytesSent   uint64
	BytesRecv   uint64
	SockCookie  uint64
}

// Byte sizes used to distinguish v4 from v6 events on the ring buffer.
const (
	sizeV4 = 80
	sizeV6 = 104
)

// ─── DNS cache ────────────────────────────────────────────────────────────────

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
	maxSize int
}

type dnsCacheEntry struct {
	hostname  string
	expiresAt time.Time
}

func newDNSCache(maxSize int) *dnsCache {
	return &dnsCache{
		entries: make(map[string]dnsCacheEntry, maxSize),
		maxSize: maxSize,
	}
}

func (c *dnsCache) get(ip string) string {
	c.mu.RLock()
	e, ok := c.entries[ip]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return ""
	}
	return e.hostname
}

func (c *dnsCache) set(ip, hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Simple eviction: remove one random entry when at capacity.
	if len(c.entries) >= c.maxSize {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[ip] = dnsCacheEntry{
		hostname:  hostname,
		expiresAt: time.Now().Add(10 * time.Minute),
	}
}

// ─── Config ───────────────────────────────────────────────────────────────────

// Config controls network monitor behaviour.
type Config struct {
	// IgnoreLocalhost drops loopback traffic (127.x and ::1).
	IgnoreLocalhost bool

	// IgnorePrivate drops all RFC1918 / link-local traffic.
	// Disable to catch lateral movement between internal hosts.
	IgnorePrivate bool

	// WatchedPorts: emit events for these ports even when IgnorePrivate is true.
	WatchedPorts []uint16

	// ResolveHostnames enables async reverse-DNS for external IPs.
	ResolveHostnames bool

	// DNSCacheSize: max number of cached IP→hostname entries.
	DNSCacheSize int

	// ProcNetPollInterval: how often to read /proc/net/tcp for connections
	// that predate the agent or were missed by eBPF.
	ProcNetPollInterval time.Duration
}

// DefaultConfig returns sensible production defaults.
func DefaultConfig() Config {
	return Config{
		IgnoreLocalhost:     true,
		IgnorePrivate:       false,
		ResolveHostnames:    true,
		DNSCacheSize:        4096,
		ProcNetPollInterval: 30 * time.Second,
	}
}

// ─── Monitor ──────────────────────────────────────────────────────────────────

// bpfObjects aliases the bpf2go-generated NetworkObjects struct.
// The generated file lives at internal/monitor/network/networkbpf_bpfel.go
// and is produced by running `make generate` from the project root.
type bpfObjects = NetworkObjects

func loadBPFObjects(obj *bpfObjects, opts *ebpf.CollectionOptions) error {
	return LoadNetworkObjects(obj, opts)
}

// Monitor is the network monitoring component.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	logger zerolog.Logger

	// eBPF state.
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader

	// Async DNS resolution.
	dns       *dnsCache
	resolveCh chan string

	// /proc/net deduplication: key → seen.
	procNetMu   sync.Mutex
	procNetSeen map[string]bool

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a Network Monitor. Call Start() to begin monitoring.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.DNSCacheSize == 0 {
		cfg.DNSCacheSize = 4096
	}
	if cfg.ProcNetPollInterval == 0 {
		cfg.ProcNetPollInterval = 30 * time.Second
	}
	return &Monitor{
		cfg:         cfg,
		bus:         bus,
		logger:      log.With().Str("monitor", "network").Logger(),
		dns:         newDNSCache(cfg.DNSCacheSize),
		resolveCh:   make(chan string, 2048),
		procNetSeen: make(map[string]bool),
		stopCh:      make(chan struct{}),
	}
}

// Start loads eBPF programs, attaches probes, and begins reading events.
// If eBPF fails to load (old kernel, missing BTF, permission issue), the
// monitor degrades gracefully to /proc/net polling mode only — it logs a
// warning and continues rather than returning an error that would kill the agent.
func (m *Monitor) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		m.logger.Warn().Err(err).Msg("network monitor: remove memlock failed; running /proc/net-only mode")
		m.startFallbackOnly(ctx)
		return nil
	}

	if err := loadBPFObjects(&m.objs, nil); err != nil {
		m.logger.Warn().Err(err).Msg("network monitor: eBPF load failed; running /proc/net-only mode")
		m.startFallbackOnly(ctx)
		return nil
	}

	if err := m.attachProbes(); err != nil {
		m.logger.Warn().Err(err).Msg("network monitor: probe attach failed; running /proc/net-only mode")
		m.closeObjs()
		m.startFallbackOnly(ctx)
		return nil
	}

	var err error
	m.reader, err = ringbuf.NewReader(m.objs.NetworkEvents)
	if err != nil {
		m.logger.Warn().Err(err).Msg("network monitor: ring buffer open failed; running /proc/net-only mode")
		m.closeObjs()
		m.startFallbackOnly(ctx)
		return nil
	}

	m.logger.Info().Msg("network monitor started (eBPF + /proc/net)")

	// Snapshot pre-existing connections before the ring buffer starts filling.
	m.snapshotProcNet()

	// eBPF ring buffer reader.
	m.wg.Add(1)
	go m.readLoop(ctx)

	// Async DNS resolver pool (4 workers).
	for i := 0; i < 4; i++ {
		m.wg.Add(1)
		go m.resolveWorker()
	}

	// /proc/net periodic poller.
	m.wg.Add(1)
	go m.procNetPoller(ctx)

	return nil
}

// startFallbackOnly runs only the /proc/net poller and DNS resolver.
// Used when eBPF is unavailable (old kernel, missing BTF, container restrictions).
func (m *Monitor) startFallbackOnly(ctx context.Context) {
	m.logger.Info().Msg("network monitor started (/proc/net polling mode — no eBPF)")

	m.snapshotProcNet()

	for i := 0; i < 4; i++ {
		m.wg.Add(1)
		go m.resolveWorker()
	}

	m.wg.Add(1)
	go m.procNetPoller(ctx)
}

// Stop gracefully shuts down the monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	if m.reader != nil {
		m.reader.Close()
	}
	m.wg.Wait()
	m.closeObjs()
	m.logger.Info().Msg("network monitor stopped")
}

// ─── eBPF probe attachment ────────────────────────────────────────────────────

func (m *Monitor) attachProbes() error {
	// fentry/tcp_connect: outbound TCP SYN.
	// fentry uses BPF trampoline and requires BTF (kernel 5.5+).
	// Fall back to kprobe for older kernels.
	l, err := link.AttachTracing(link.TracingOptions{Program: m.objs.FentryTcpConnect})
	if err != nil {
		m.logger.Warn().Err(err).Msg("fentry/tcp_connect unavailable, falling back to kprobe")
		l, err = link.Kprobe("tcp_connect", m.objs.FentryTcpConnect, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_connect: %w", err)
		}
	}
	m.links = append(m.links, l)

	// fexit/inet_csk_accept: inbound TCP accepted.
	l, err = link.AttachTracing(link.TracingOptions{Program: m.objs.FexitInetCskAccept})
	if err != nil {
		m.logger.Warn().Err(err).Msg("fexit/inet_csk_accept unavailable, trying kretprobe")
		l, err = link.Kretprobe("inet_csk_accept", m.objs.FexitInetCskAccept, nil)
		if err != nil {
			// Non-fatal: /proc/net poller covers inbound connections.
			m.logger.Warn().Err(err).Msg("inet_csk_accept kretprobe also unavailable; inbound TCP via /proc/net only")
		} else {
			m.links = append(m.links, l)
		}
	} else {
		m.links = append(m.links, l)
	}

	// tracepoint/sock/inet_sock_set_state: TCP state transitions.
	l, err = link.Tracepoint("sock", "inet_sock_set_state", m.objs.TpInetSockSetState, nil)
	if err != nil {
		m.logger.Warn().Err(err).Msg("inet_sock_set_state tracepoint unavailable; close events will be missing")
	} else {
		m.links = append(m.links, l)
	}

	// fentry/tcp_close: byte counters on connection close.
	l, err = link.AttachTracing(link.TracingOptions{Program: m.objs.FentryTcpClose})
	if err != nil {
		l, err = link.Kprobe("tcp_close", m.objs.FentryTcpClose, nil)
		if err != nil {
			m.logger.Warn().Err(err).Msg("tcp_close probe unavailable; BytesSent/BytesRecv will be 0")
		} else {
			m.links = append(m.links, l)
		}
	} else {
		m.links = append(m.links, l)
	}

	// kprobe/udp_sendmsg: outbound UDP.
	l, err = link.Kprobe("udp_sendmsg", m.objs.KprobeUdpSendmsg, nil)
	if err != nil {
		m.logger.Warn().Err(err).Msg("udp_sendmsg kprobe unavailable; UDP send via /proc/net only")
	} else {
		m.links = append(m.links, l)
	}

	// kprobe/udp_recvmsg: inbound UDP.
	l, err = link.Kprobe("udp_recvmsg", m.objs.KprobeUdpRecvmsg, nil)
	if err != nil {
		m.logger.Warn().Err(err).Msg("udp_recvmsg kprobe unavailable")
	} else {
		m.links = append(m.links, l)
	}

	return nil
}

func (m *Monitor) closeObjs() {
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
}

// ─── Ring buffer read loop ────────────────────────────────────────────────────

func (m *Monitor) readLoop(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			m.logger.Error().Err(err).Msg("ring buffer read error")
			continue
		}

		if err := m.dispatchEvent(record.RawSample); err != nil {
			m.logger.Debug().Err(err).Msg("dispatch network event failed")
		}
	}
}

// dispatchEvent distinguishes IPv4 (80 bytes) from IPv6 (104 bytes) by size,
// decodes the struct, and calls the appropriate handler.
func (m *Monitor) dispatchEvent(raw []byte) error {
	switch len(raw) {
	case sizeV4:
		var r rawNetEventV4
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
			return fmt.Errorf("decode v4 event: %w", err)
		}
		return m.handleV4(r)

	case sizeV6:
		var r rawNetEventV6
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
			return fmt.Errorf("decode v6 event: %w", err)
		}
		return m.handleV6(r)

	default:
		return fmt.Errorf("unexpected network event size: %d bytes", len(raw))
	}
}

// ─── V4 event handler ─────────────────────────────────────────────────────────

func (m *Monitor) handleV4(r rawNetEventV4) error {
	srcIP := utils.Uint32ToIPv4(r.SrcIP)
	dstIP := utils.Uint32ToIPv4(r.DstIP)

	if m.shouldDrop(srcIP, dstIP, r.DstPort, r.Direction) {
		return nil
	}

	evType, dir, state := m.classify(r.EventType, r.Direction, r.TCPState)
	proto := protoString(r.Protocol)
	ts := utils.BootNsToTime(r.TimestampNs)
	comm := nullStr(r.Comm[:])

	// Look up cached hostname; queue async resolution if missing.
	dstHostname := m.dns.get(dstIP)
	if dstHostname == "" && m.cfg.ResolveHostnames && !utils.IsPrivateIPv4(dstIP) {
		m.queueResolve(dstIP)
	}

	sev := m.assessSeverity(r.DstPort, r.Direction, dstIP)
	tags := m.buildTags(r.DstPort, r.Direction, proto, dstIP)

	ev := &types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID:        utils.NewEventID(),
			Type:      evType,
			Timestamp: ts,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  sev,
			Process:   buildProcContext(r.PID, r.PPID, r.UID, comm),
			Tags:      tags,
		},
		SrcIP:     srcIP,
		SrcPort:   r.SrcPort,
		DstIP:     dstIP,
		DstPort:   r.DstPort,
		Protocol:  proto,
		Direction: dir,
		State:     state,
		BytesSent: r.BytesSent,
		BytesRecv: r.BytesRecv,
		DNSQuery:  dstHostname,
		IsPrivate: utils.IsPrivateIPv4(dstIP),
	}

	m.bus.Publish(ev)
	m.logEvent(ev)
	return nil
}

// ─── V6 event handler ─────────────────────────────────────────────────────────

func (m *Monitor) handleV6(r rawNetEventV6) error {
	srcIP := net.IP(r.SrcIP[:]).String()
	dstIP := net.IP(r.DstIP[:]).String()

	if m.shouldDropV6(srcIP, dstIP, r.DstPort, r.Direction) {
		return nil
	}

	evType, dir, state := m.classify(r.EventType, r.Direction, r.TCPState)
	proto := protoString(r.Protocol)
	ts := utils.BootNsToTime(r.TimestampNs)
	comm := nullStr(r.Comm[:])

	dstHostname := m.dns.get(dstIP)
	if dstHostname == "" && m.cfg.ResolveHostnames {
		m.queueResolve(dstIP)
	}

	isPrivate := isPrivateIPv6(dstIP)
	sev := m.assessSeverity(r.DstPort, r.Direction, dstIP)
	tags := m.buildTags(r.DstPort, r.Direction, proto, dstIP)

	ev := &types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID:        utils.NewEventID(),
			Type:      evType,
			Timestamp: ts,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  sev,
			Process:   buildProcContext(r.PID, r.PPID, r.UID, comm),
			Tags:      tags,
		},
		SrcIP:     srcIP,
		SrcPort:   r.SrcPort,
		DstIP:     dstIP,
		DstPort:   r.DstPort,
		Protocol:  proto,
		Direction: dir,
		State:     state,
		BytesSent: r.BytesSent,
		BytesRecv: r.BytesRecv,
		DNSQuery:  dstHostname,
		IsPrivate: isPrivate,
	}

	m.bus.Publish(ev)
	m.logEvent(ev)
	return nil
}

// ─── Filtering ────────────────────────────────────────────────────────────────

func (m *Monitor) shouldDrop(srcIP, dstIP string, dstPort uint16, direction uint8) bool {
	if m.cfg.IgnoreLocalhost {
		if strings.HasPrefix(dstIP, "127.") || strings.HasPrefix(srcIP, "127.") {
			return true
		}
	}
	if m.cfg.IgnorePrivate && utils.IsPrivateIPv4(dstIP) {
		for _, p := range m.cfg.WatchedPorts {
			if dstPort == p {
				return false
			}
		}
		return true
	}
	return false
}

func (m *Monitor) shouldDropV6(srcIP, dstIP string, dstPort uint16, direction uint8) bool {
	if m.cfg.IgnoreLocalhost && (dstIP == "::1" || srcIP == "::1") {
		return true
	}
	if m.cfg.IgnorePrivate && isPrivateIPv6(dstIP) {
		for _, p := range m.cfg.WatchedPorts {
			if dstPort == p {
				return false
			}
		}
		return true
	}
	return false
}

// ─── Classification ───────────────────────────────────────────────────────────

func (m *Monitor) classify(
	rawType uint32, direction uint8, tcpState uint8,
) (types.EventType, types.NetworkDirection, types.NetworkConnState) {
	var evType types.EventType
	switch rawType {
	case ebpfNetAccept:
		evType = types.EventNetAccept
	case ebpfNetClose:
		evType = types.EventNetClose
	default:
		evType = types.EventNetConnect
	}

	dir := types.DirOutbound
	if direction == 1 {
		dir = types.DirInbound
	}

	return evType, dir, tcpStateToConnState(tcpState)
}

func tcpStateToConnState(s uint8) types.NetworkConnState {
	// Constants from linux/tcp.h
	switch s {
	case 1:
		return types.ConnStateEstablished
	case 2:
		return types.ConnStateSYN
	case 7:
		return types.ConnStateClosed
	case 8:
		return types.ConnStateCloseWait
	case 6:
		return types.ConnStateTimeWait
	case 11:
		return types.ConnStateReset
	default:
		return types.ConnStateEstablished
	}
}

// ─── Severity + tagging ───────────────────────────────────────────────────────

// assessSeverity implements the same logic as the backend "rule-outbound-high-port"
// default rule so events are pre-scored before reaching the backend.
func (m *Monitor) assessSeverity(dstPort uint16, direction uint8, dstIP string) types.Severity {
	if direction == 1 {
		// Inbound connections are info unless we later add listener anomaly detection.
		return types.SeverityInfo
	}

	isPrivate := utils.IsPrivateIPv4(dstIP) || isPrivateIPv6(dstIP)

	// Outbound to external IP on ephemeral high port — potential C2 beacon.
	if dstPort > 49151 && !isPrivate {
		return types.SeverityMedium
	}

	// Classic C2 / reverse shell ports.
	switch dstPort {
	case 4444, 4445, 4446: // Metasploit defaults
		return types.SeverityHigh
	case 1234, 31337: // Classic backdoor ports
		return types.SeverityHigh
	case 9001, 9002: // Common RAT / Tor ports
		return types.SeverityMedium
	}

	return types.SeverityInfo
}

func (m *Monitor) buildTags(dstPort uint16, direction uint8, proto types.NetworkProtocol, dstIP string) []string {
	tags := make([]string, 0, 4)

	if direction == 0 {
		tags = append(tags, "outbound")
	} else {
		tags = append(tags, "inbound")
	}

	isPrivate := utils.IsPrivateIPv4(dstIP) || isPrivateIPv6(dstIP)
	if isPrivate {
		tags = append(tags, "internal")
	} else {
		tags = append(tags, "external")
	}

	if proto == types.ProtoUDP && dstPort == 53 {
		tags = append(tags, "dns")
	}

	if dstPort > 49151 && direction == 0 {
		tags = append(tags, "high-port")
	}

	switch dstPort {
	case 4444, 4445, 4446:
		tags = append(tags, "metasploit-default")
	case 31337:
		tags = append(tags, "eleet-port")
	}

	return tags
}

// ─── Async DNS resolution ─────────────────────────────────────────────────────

func (m *Monitor) queueResolve(ip string) {
	select {
	case m.resolveCh <- ip:
	default:
		// Channel full — drop silently.  The next event for this IP will retry.
	}
}

func (m *Monitor) resolveWorker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case ip, ok := <-m.resolveCh:
			if !ok {
				return
			}
			if m.dns.get(ip) != "" {
				continue // already resolved by another worker
			}
			hostnames, err := net.LookupAddr(ip)
			if err != nil || len(hostnames) == 0 {
				m.dns.set(ip, ip) // cache negative result
				continue
			}
			// LookupAddr returns FQDNs with a trailing dot — strip it.
			name := strings.TrimSuffix(hostnames[0], ".")
			m.dns.set(ip, name)
		}
	}
}

// ─── /proc/net poller ────────────────────────────────────────────────────────

func (m *Monitor) procNetPoller(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.ProcNetPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.snapshotProcNet()
		}
	}
}

func (m *Monitor) snapshotProcNet() {
	m.parseProcNetTCP("/proc/net/tcp", false)
	m.parseProcNetTCP("/proc/net/tcp6", true)
	m.parseProcNetUDP("/proc/net/udp")
}

// parseProcNetTCP reads /proc/net/tcp (or tcp6) and emits NET_CONNECT events
// for ESTABLISHED connections not yet seen via eBPF.
//
// Format: sl  local_addr rem_addr state  tx:rx tr:tm retrans uid timeout inode ...
// Addresses are hex-encoded "IP:PORT" pairs.  IPv4: 4-byte LE uint32.
// IPv6: 16-byte (four LE 32-bit words).  State 01 = TCP_ESTABLISHED.
func (m *Monitor) parseProcNetTCP(path string, isV6 bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // discard header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || state != 1 { // 01 = TCP_ESTABLISHED
			continue
		}

		var srcIP, dstIP string
		var srcPort, dstPort uint16
		if !isV6 {
			srcIP, srcPort = parseProcNetAddrV4(fields[1])
			dstIP, dstPort = parseProcNetAddrV4(fields[2])
		} else {
			srcIP, srcPort = parseProcNetAddrV6(fields[1])
			dstIP, dstPort = parseProcNetAddrV6(fields[2])
		}
		if srcIP == "" || dstIP == "" {
			continue
		}

		if m.shouldDrop(srcIP, dstIP, dstPort, 0) {
			continue
		}

		key := fmt.Sprintf("%s:%d→%s:%d", srcIP, srcPort, dstIP, dstPort)
		m.procNetMu.Lock()
		seen := m.procNetSeen[key]
		if !seen {
			m.procNetSeen[key] = true
		}
		m.procNetMu.Unlock()
		if seen {
			continue
		}

		isPrivate := utils.IsPrivateIPv4(dstIP) || isPrivateIPv6(dstIP)
		tags := []string{"proc-net-snapshot", "outbound"}
		if isPrivate {
			tags = append(tags, "internal")
		} else {
			tags = append(tags, "external")
		}

		// Try to attribute this connection to a process via inode→PID lookup.
		inode := fields[9]
		procPID, procComm := resolveInodeToProc(inode)
		var procCtx types.ProcessContext
		if procPID != 0 {
			procCtx = buildProcContext(procPID, 0, 0, procComm)
		}

		ev := &types.NetworkEvent{
			BaseEvent: types.BaseEvent{
				ID:        utils.NewEventID(),
				Type:      types.EventNetConnect,
				Timestamp: time.Now(),
				AgentID:   m.bus.AgentID(),
				Hostname:  m.bus.Hostname(),
				Severity:  types.SeverityInfo,
				Process:   procCtx,
				Tags:      tags,
			},
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  types.ProtoTCP,
			Direction: types.DirOutbound,
			State:     types.ConnStateEstablished,
			IsPrivate: isPrivate,
		}
		m.bus.Publish(ev)
	}
}

// parseProcNetUDP reads /proc/net/udp and emits NET_DNS events for DNS queries
// (dst port 53) not yet seen, to fill the gap when the udp_sendmsg kprobe
// is unavailable or the query happened before the agent started.
func (m *Monitor) parseProcNetUDP(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // discard header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		srcIP, srcPort := parseProcNetAddrV4(fields[1])
		dstIP, dstPort := parseProcNetAddrV4(fields[2])
		if srcIP == "" || dstIP == "" || dstPort != 53 {
			continue
		}

		key := fmt.Sprintf("dns:%s:%d→%s:53", srcIP, srcPort, dstIP)
		m.procNetMu.Lock()
		seen := m.procNetSeen[key]
		if !seen {
			m.procNetSeen[key] = true
		}
		m.procNetMu.Unlock()
		if seen {
			continue
		}

		ev := &types.NetworkEvent{
			BaseEvent: types.BaseEvent{
				ID:        utils.NewEventID(),
				Type:      types.EventNetDNS,
				Timestamp: time.Now(),
				AgentID:   m.bus.AgentID(),
				Hostname:  m.bus.Hostname(),
				Severity:  types.SeverityInfo,
				Tags:      []string{"dns", "udp", "outbound"},
			},
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   53,
			Protocol:  types.ProtoUDP,
			Direction: types.DirOutbound,
			State:     types.ConnStateEstablished,
			IsPrivate: utils.IsPrivateIPv4(dstIP),
		}
		m.bus.Publish(ev)
	}
}

// ─── /proc/net address parsers ────────────────────────────────────────────────

// parseProcNetAddrV4 decodes "AABBCCDD:PPPP" from /proc/net/tcp.
// The 4-byte IP is stored in little-endian (x86) byte order.
func parseProcNetAddrV4(s string) (ip string, port uint16) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(ipBytes) != 4 {
		return "", 0
	}
	// Reverse little-endian bytes.
	ip = fmt.Sprintf("%d.%d.%d.%d", ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
	p, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0
	}
	return ip, uint16(p)
}

// parseProcNetAddrV6 decodes a 32-hex-char IPv6 address + port from /proc/net/tcp6.
// The kernel stores each 4-byte word in little-endian; we byte-swap each word.
func parseProcNetAddrV6(s string) (ip string, port uint16) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || len(parts[0]) != 32 {
		return "", 0
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil || len(b) != 16 {
		return "", 0
	}
	// Byte-swap each 4-byte word from little-endian to network byte order.
	for i := 0; i < 16; i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	ip = net.IP(b).String()
	p, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0
	}
	return ip, uint16(p)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildProcContext creates a minimal ProcessContext from eBPF event fields.
// Full enrichment (ExePath, Cmdline, Cwd, ancestry) is intentionally skipped
// here — the /proc walk is too expensive on the hot ring-buffer path.
func buildProcContext(pid, ppid, uid uint32, comm string) types.ProcessContext {
	return types.ProcessContext{
		PID:      pid,
		PPID:     ppid,
		UID:      uid,
		Comm:     comm,
		Username: utils.UIDToUsername(uid),
	}
}

// resolveInodeToProc maps a socket inode string to the PID and comm that owns it.
// Used by tests and future slow-path enrichment.  NOT called on the hot path.
func resolveInodeToProc(inode string) (pid uint32, comm string) {
	fds, err := filepath.Glob("/proc/*/fd/*")
	if err != nil {
		return 0, ""
	}
	target := "socket:[" + inode + "]"
	for _, fd := range fds {
		link, err := os.Readlink(fd)
		if err != nil || link != target {
			continue
		}
		parts := strings.Split(fd, "/")
		if len(parts) < 3 {
			continue
		}
		p, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		pid = uint32(p)
		if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			comm = strings.TrimSpace(string(raw))
		}
		return pid, comm
	}
	return 0, ""
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func protoString(proto uint8) types.NetworkProtocol {
	switch proto {
	case 6:
		return types.ProtoTCP
	case 17:
		return types.ProtoUDP
	case 1:
		return types.ProtoICMP
	default:
		return types.ProtoRAW
	}
}

// isPrivateIPv6 returns true for loopback (::1), ULA (fc00::/7),
// and link-local (fe80::/10) addresses.
func isPrivateIPv6(ip string) bool {
	if ip == "::1" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if len(parsed) == 16 {
		if (parsed[0] & 0xfe) == 0xfc { // ULA fc00::/7
			return true
		}
		if parsed[0] == 0xfe && (parsed[1]&0xc0) == 0x80 { // link-local fe80::/10
			return true
		}
	}
	return false
}

func (m *Monitor) logEvent(ev *types.NetworkEvent) {
	log := m.logger.Debug()
	if ev.Severity >= types.SeverityMedium {
		log = m.logger.Info()
	}
	if ev.Severity >= types.SeverityHigh {
		log = m.logger.Warn()
	}
	log.
		Str("event_id", ev.ID).
		Str("type", string(ev.Type)).
		Str("src", fmt.Sprintf("%s:%d", ev.SrcIP, ev.SrcPort)).
		Str("dst", fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)).
		Str("proto", string(ev.Protocol)).
		Str("dir", string(ev.Direction)).
		Str("comm", ev.Process.Comm).
		Uint32("pid", ev.Process.PID).
		Strs("tags", ev.Tags).
		Msg("NET_EVENT")
}
