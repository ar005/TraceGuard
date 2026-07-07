package network

import (
	"encoding/binary"
	"testing"
)

func TestParseIPv4NetEvent(t *testing.T) {
	// PID=1234, size=0, daddr=93.184.216.34 (example.com), saddr=192.168.1.100, dport=443, sport=54321
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:4], 1234)
	binary.LittleEndian.PutUint32(data[4:8], 0)
	copy(data[8:12], []byte{93, 184, 216, 34})    // daddr
	copy(data[12:16], []byte{192, 168, 1, 100})   // saddr
	binary.BigEndian.PutUint16(data[16:18], 443)  // dport
	binary.BigEndian.PutUint16(data[18:20], 54321) // sport

	ev, ok := parseIPv4NetEvent(data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", ev.PID)
	}
	if ev.DstIP != "93.184.216.34" {
		t.Errorf("DstIP: got %q, want %q", ev.DstIP, "93.184.216.34")
	}
	if ev.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP: got %q, want %q", ev.SrcIP, "192.168.1.100")
	}
	if ev.DstPort != 443 {
		t.Errorf("DstPort: got %d, want 443", ev.DstPort)
	}
	if ev.SrcPort != 54321 {
		t.Errorf("SrcPort: got %d, want 54321", ev.SrcPort)
	}
}

func TestParseIPv4NetEvent_Short(t *testing.T) {
	_, ok := parseIPv4NetEvent(make([]byte, 19))
	if ok {
		t.Fatal("expected ok=false for 19-byte payload")
	}
	_, ok = parseIPv4NetEvent(nil)
	if ok {
		t.Fatal("expected ok=false for nil payload")
	}
}

func TestParseIPv6NetEvent(t *testing.T) {
	// PID=9999, daddr=::1 (loopback), saddr=::2, dport=8080, sport=12345
	data := make([]byte, 44)
	binary.LittleEndian.PutUint32(data[0:4], 9999)
	binary.LittleEndian.PutUint32(data[4:8], 512)
	// daddr: 16 bytes starting at offset 8 — ::1
	data[23] = 1
	// saddr: 16 bytes starting at offset 24 — ::2
	data[39] = 2
	binary.BigEndian.PutUint16(data[40:42], 8080)
	binary.BigEndian.PutUint16(data[42:44], 12345)

	ev, ok := parseIPv6NetEvent(data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.PID != 9999 {
		t.Errorf("PID: got %d, want 9999", ev.PID)
	}
	if ev.DstIP != "::1" {
		t.Errorf("DstIP: got %q, want ::1", ev.DstIP)
	}
	if ev.SrcIP != "::2" {
		t.Errorf("SrcIP: got %q, want ::2", ev.SrcIP)
	}
	if ev.DstPort != 8080 {
		t.Errorf("DstPort: got %d, want 8080", ev.DstPort)
	}
	if ev.SrcPort != 12345 {
		t.Errorf("SrcPort: got %d, want 12345", ev.SrcPort)
	}
}

func TestParseIPv6NetEvent_Short(t *testing.T) {
	_, ok := parseIPv6NetEvent(make([]byte, 43))
	if ok {
		t.Fatal("expected ok=false for 43-byte payload")
	}
}

func TestIsPrivateIP(t *testing.T) {
	private := []string{"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "127.0.0.1"}
	for _, ip := range private {
		if !isPrivateIP(ip) {
			t.Errorf("expected %s to be private", ip)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, ip := range public {
		if isPrivateIP(ip) {
			t.Errorf("expected %s to be public", ip)
		}
	}
}

func TestIsPrivateIPv6(t *testing.T) {
	if !isPrivateIPv6("::1") {
		t.Error("::1 should be private")
	}
	if !isPrivateIPv6("fc00::1") {
		t.Error("fc00::1 should be private (ULA)")
	}
	if !isPrivateIPv6("fe80::1") {
		t.Error("fe80::1 should be private (link-local)")
	}
	if isPrivateIPv6("2001:4860:4860::8888") {
		t.Error("Google DNS should not be private")
	}
}

func TestIsLoopback(t *testing.T) {
	if !isLoopback("127.0.0.1") {
		t.Error("127.0.0.1 should be loopback")
	}
	if !isLoopback("::1") {
		t.Error("::1 should be loopback")
	}
	if isLoopback("192.168.1.1") {
		t.Error("192.168.1.1 should not be loopback")
	}
	if isLoopback("not-an-ip") {
		t.Error("invalid IP should not be loopback")
	}
}
