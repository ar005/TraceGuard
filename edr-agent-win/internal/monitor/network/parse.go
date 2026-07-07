// parse.go — pure-Go network event payload parsers. No OS-specific imports.
// Split out so tests can run on Linux CI without the Windows build tag.
package network

import (
	"encoding/binary"
	"net"
)

// ipv4NetEvent holds parsed fields from a Kernel-Network IPv4 event UserData.
type ipv4NetEvent struct {
	PID     uint32
	DstIP   string
	SrcIP   string
	DstPort uint16
	SrcPort uint16
}

// parseIPv4NetEvent parses the 20-byte UserData from Kernel-Network IPv4 events
// (TcpConnect=10, TcpDisconnect=11, TcpAccept=14, UdpSend=26, UdpReceive=27).
//
//	Offset  Size  Field
//	0       4     PID   (uint32 LE — process owning the socket)
//	4       4     size  (uint32 LE — bytes transferred; discarded)
//	8       4     daddr (IPv4 in network byte order — remote/destination)
//	12      4     saddr (IPv4 in network byte order — local/source)
//	16      2     dport (uint16 big-endian — remote/destination port)
//	18      2     sport (uint16 big-endian — local/source port)
func parseIPv4NetEvent(data []byte) (ipv4NetEvent, bool) {
	if len(data) < 20 {
		return ipv4NetEvent{}, false
	}
	return ipv4NetEvent{
		PID:     binary.LittleEndian.Uint32(data[0:4]),
		DstIP:   net.IP(data[8:12]).String(),
		SrcIP:   net.IP(data[12:16]).String(),
		DstPort: binary.BigEndian.Uint16(data[16:18]),
		SrcPort: binary.BigEndian.Uint16(data[18:20]),
	}, true
}

// ipv6NetEvent holds parsed fields from a Kernel-Network IPv6 event UserData.
type ipv6NetEvent struct {
	PID     uint32
	DstIP   string
	SrcIP   string
	DstPort uint16
	SrcPort uint16
}

// parseIPv6NetEvent parses the 44-byte UserData from Kernel-Network IPv6 events
// (TcpV6Connect=58, TcpV6Disconnect=61, UdpV6Send=67, UdpV6Receive=68).
//
//	Offset  Size  Field
//	0       4     PID   (uint32 LE)
//	4       4     size  (uint32 LE; discarded)
//	8       16    daddr (IPv6 in network byte order — remote/destination)
//	24      16    saddr (IPv6 in network byte order — local/source)
//	40      2     dport (uint16 big-endian)
//	42      2     sport (uint16 big-endian)
func parseIPv6NetEvent(data []byte) (ipv6NetEvent, bool) {
	if len(data) < 44 {
		return ipv6NetEvent{}, false
	}
	return ipv6NetEvent{
		PID:     binary.LittleEndian.Uint32(data[0:4]),
		DstIP:   net.IP(data[8:24]).String(),
		SrcIP:   net.IP(data[24:40]).String(),
		DstPort: binary.BigEndian.Uint16(data[40:42]),
		SrcPort: binary.BigEndian.Uint16(data[42:44]),
	}, true
}

// isPrivateIP reports whether an IPv4 address string falls in RFC1918 / loopback ranges.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range privateIPv4Ranges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateIPv6 reports whether an IPv6 address string falls in ULA / link-local / loopback ranges.
func isPrivateIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range privateIPv6Ranges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// isLoopback reports whether an IP string (v4 or v6) is a loopback address.
func isLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.IsLoopback()
}

var (
	privateIPv4Ranges = mustParseCIDRs([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	})
	privateIPv6Ranges = mustParseCIDRs([]string{
		"fc00::/7",  // Unique Local Addresses (ULA)
		"fe80::/10", // Link-local
		"::1/128",   // Loopback
	})
)

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("bad CIDR: " + c)
		}
		nets = append(nets, n)
	}
	return nets
}
