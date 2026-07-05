package etw

import (
	"testing"
)

func TestReadUint32(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0xFF}
	v, next := ReadUint32(data, 0)
	if v != 0x04030201 {
		t.Fatalf("got %#x, want 0x04030201", v)
	}
	if next != 4 {
		t.Fatalf("next offset got %d, want 4", next)
	}

	// Short read: not enough bytes.
	v2, next2 := ReadUint32(data, 3)
	if v2 != 0 || next2 != 3 {
		t.Fatalf("short read: got (%d, %d), want (0, 3)", v2, next2)
	}
}

func TestReadUint16(t *testing.T) {
	data := []byte{0xAB, 0xCD}
	v, next := ReadUint16(data, 0)
	if v != 0xCDAB {
		t.Fatalf("got %#x, want 0xCDAB", v)
	}
	if next != 2 {
		t.Fatalf("next offset got %d, want 2", next)
	}
}

func TestReadPortBE(t *testing.T) {
	// Port 443 in big-endian: 0x01BB
	data := []byte{0x01, 0xBB}
	port, next := ReadPortBE(data, 0)
	if port != 443 {
		t.Fatalf("got %d, want 443", port)
	}
	if next != 2 {
		t.Fatalf("next offset got %d, want 2", next)
	}

	// Port 80: 0x0050
	data2 := []byte{0x00, 0x50}
	port2, _ := ReadPortBE(data2, 0)
	if port2 != 80 {
		t.Fatalf("got %d, want 80", port2)
	}
}

func TestReadIPv4(t *testing.T) {
	data := []byte{192, 168, 1, 100}
	ip, next := ReadIPv4(data, 0)
	if ip != "192.168.1.100" {
		t.Fatalf("got %q, want %q", ip, "192.168.1.100")
	}
	if next != 4 {
		t.Fatalf("next offset got %d, want 4", next)
	}

	// Short: only 3 bytes.
	_, next2 := ReadIPv4(data[:3], 0)
	if next2 != 0 {
		t.Fatalf("short read: next offset got %d, want 0", next2)
	}
}

func TestReadIPv6(t *testing.T) {
	// ::1 (loopback)
	data := make([]byte, 16)
	data[15] = 1
	ip, next := ReadIPv6(data, 0)
	if ip != "::1" {
		t.Fatalf("got %q, want %q", ip, "::1")
	}
	if next != 16 {
		t.Fatalf("next offset got %d, want 16", next)
	}
}

func TestReadUTF16NullTerminated(t *testing.T) {
	// "cmd" in UTF-16LE: c=0x63,0x00 m=0x6D,0x00 d=0x64,0x00 null=0x00,0x00
	data := []byte{0x63, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x00, 0x00}
	s, next := ReadUTF16NullTerminated(data, 0)
	if s != "cmd" {
		t.Fatalf("got %q, want %q", s, "cmd")
	}
	if next != 8 {
		t.Fatalf("next offset got %d, want 8", next)
	}

	// Empty string: immediately null-terminated.
	data2 := []byte{0x00, 0x00}
	s2, next2 := ReadUTF16NullTerminated(data2, 0)
	if s2 != "" {
		t.Fatalf("got %q, want empty", s2)
	}
	if next2 != 2 {
		t.Fatalf("next offset got %d, want 2", next2)
	}

	// No null terminator: reads to end of data.
	data3 := []byte{0x41, 0x00} // "A" with no terminator
	s3, _ := ReadUTF16NullTerminated(data3, 0)
	if s3 != "A" {
		t.Fatalf("got %q, want A", s3)
	}
}

func TestReadUTF16NullTerminated_MultipleStrings(t *testing.T) {
	// Two strings packed: "ab\0cd\0" in UTF-16LE
	//   a=0x61,0x00  b=0x62,0x00  \0=0x00,0x00  c=0x63,0x00  d=0x64,0x00  \0=0x00,0x00
	data := []byte{
		0x61, 0x00, 0x62, 0x00, 0x00, 0x00, // "ab\0"
		0x63, 0x00, 0x64, 0x00, 0x00, 0x00, // "cd\0"
	}
	s1, next := ReadUTF16NullTerminated(data, 0)
	if s1 != "ab" {
		t.Fatalf("first string: got %q, want %q", s1, "ab")
	}
	s2, _ := ReadUTF16NullTerminated(data, next)
	if s2 != "cd" {
		t.Fatalf("second string: got %q, want %q", s2, "cd")
	}
}

func TestSkip(t *testing.T) {
	if Skip(4, 8) != 12 {
		t.Fatal("Skip(4,8) should be 12")
	}
}
