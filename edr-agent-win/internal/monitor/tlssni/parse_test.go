package tlssni

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildClientHello builds a minimal TLS record containing a ClientHello with
// the given SNI hostname.  The ClientHello version is set to 0x0303 (TLS 1.2).
func buildClientHello(sni string) []byte {
	sniBytes := []byte(sni)

	// SNI extension data: list_len(2) + name_type(1) + name_len(2) + name
	extData := make([]byte, 5+len(sniBytes))
	binary.BigEndian.PutUint16(extData[0:2], uint16(3+len(sniBytes))) // list len
	extData[2] = 0x00                                                   // host_name
	binary.BigEndian.PutUint16(extData[3:5], uint16(len(sniBytes)))
	copy(extData[5:], sniBytes)

	// Extension: type(2) + data_len(2) + data
	ext := make([]byte, 4+len(extData))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000) // server_name
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(extData)))
	copy(ext[4:], extData)

	// ClientHello body
	body := []byte{0x03, 0x03}    // version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session ID length
	body = append(body, 0x00, 0x02)          // cipher suites length
	body = append(body, 0x00, 0x2f)          // TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0x01)                // compression methods length
	body = append(body, 0x00)                // no compression
	extsLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(extsLenBuf, uint16(len(ext)))
	body = append(body, extsLenBuf...)
	body = append(body, ext...)

	// Handshake: type(1) + length(3) + body
	hs := make([]byte, 4+len(body))
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	// TLS record: content_type(1) + version(2) + length(2) + handshake
	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // Handshake
	rec[1] = 0x03
	rec[2] = 0x01 // compat record version TLS 1.0
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// buildClientHelloNoSNI builds a ClientHello with no extensions at all.
func buildClientHelloNoSNI() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02)
	body = append(body, 0x00, 0x2f)
	body = append(body, 0x01)
	body = append(body, 0x00)
	// No extensions block at all.

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func TestParseTLSClientHelloSNI_Basic(t *testing.T) {
	pkt := buildClientHello("example.com")
	sni, ver := parseTLSClientHelloSNI(pkt)
	if sni != "example.com" {
		t.Errorf("sni: got %q, want %q", sni, "example.com")
	}
	if ver != "TLS 1.2" {
		t.Errorf("version: got %q, want %q", ver, "TLS 1.2")
	}
}

func TestParseTLSClientHelloSNI_LongDomain(t *testing.T) {
	domain := "very-long-subdomain.deeply.nested.example.internal.corp"
	pkt := buildClientHello(domain)
	sni, _ := parseTLSClientHelloSNI(pkt)
	if sni != domain {
		t.Errorf("sni: got %q, want %q", sni, domain)
	}
}

func TestParseTLSClientHelloSNI_NotTLS(t *testing.T) {
	pkt := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sni, ver := parseTLSClientHelloSNI(pkt)
	if sni != "" || ver != "" {
		t.Errorf("expected empty result for non-TLS data, got sni=%q ver=%q", sni, ver)
	}
}

func TestParseTLSClientHelloSNI_TooShort(t *testing.T) {
	sni, ver := parseTLSClientHelloSNI([]byte{0x16, 0x03, 0x03})
	if sni != "" || ver != "" {
		t.Errorf("expected empty for too-short input, got sni=%q ver=%q", sni, ver)
	}
}

func TestParseTLSClientHelloSNI_Nil(t *testing.T) {
	sni, ver := parseTLSClientHelloSNI(nil)
	if sni != "" || ver != "" {
		t.Errorf("expected empty for nil input, got sni=%q ver=%q", sni, ver)
	}
}

func TestParseTLSClientHelloSNI_NoSNI(t *testing.T) {
	pkt := buildClientHelloNoSNI()
	sni, ver := parseTLSClientHelloSNI(pkt)
	if sni != "" {
		t.Errorf("sni: expected empty for ClientHello without SNI, got %q", sni)
	}
	if ver != "TLS 1.2" {
		t.Errorf("version: got %q, want %q", ver, "TLS 1.2")
	}
}

func TestParseTLSClientHelloSNI_WrongContentType(t *testing.T) {
	pkt := buildClientHello("example.com")
	pkt[0] = 0x17 // Application Data — not Handshake
	sni, _ := parseTLSClientHelloSNI(pkt)
	if sni != "" {
		t.Errorf("expected empty sni for non-handshake record, got %q", sni)
	}
}

func TestParseTLSClientHelloSNI_WrongHandshakeType(t *testing.T) {
	pkt := buildClientHello("example.com")
	// The handshake type byte is at offset 5 (after TLS record header).
	pkt[5] = 0x02 // ServerHello — not ClientHello
	sni, _ := parseTLSClientHelloSNI(pkt)
	if sni != "" {
		t.Errorf("expected empty sni for non-ClientHello handshake, got %q", sni)
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		major, minor byte
		want         string
	}{
		{3, 1, "TLS 1.0"},
		{3, 2, "TLS 1.1"},
		{3, 3, "TLS 1.2"},
		{3, 4, "TLS 1.3"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.major, tt.minor)
		if got != tt.want {
			t.Errorf("tlsVersionString(%d,%d): got %q, want %q", tt.major, tt.minor, got, tt.want)
		}
	}
}

func TestDeduper_FirstCallNotSeen(t *testing.T) {
	d := newDeduper()
	if d.seen("key1") {
		t.Error("first call to seen should return false")
	}
}

func TestDeduper_SecondCallSeen(t *testing.T) {
	d := newDeduper()
	d.seen("key1")
	if !d.seen("key1") {
		t.Error("second call with same key should return true (within window)")
	}
}

func TestDeduper_DifferentKeys(t *testing.T) {
	d := newDeduper()
	d.seen("key1")
	if d.seen("key2") {
		t.Error("different key should not be seen")
	}
}

func TestDeduper_ExpiredEntry(t *testing.T) {
	d := newDeduper()
	// Manually insert an expired entry.
	d.mu.Lock()
	d.entries["stale"] = time.Now().Add(-time.Second)
	d.mu.Unlock()
	if d.seen("stale") {
		t.Error("expired entry should not be seen")
	}
}
