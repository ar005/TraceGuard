package tlssni

import (
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a synthetic TLS ClientHello with the given SNI domain
// and TLS record version (major, minor).
func buildClientHello(domain string, major, minor byte) []byte {
	// Build SNI extension data.
	nameBytes := []byte(domain)
	// SNI extension: list_length(2) + name_type(1) + name_length(2) + name
	sniExtData := make([]byte, 2+1+2+len(nameBytes))
	binary.BigEndian.PutUint16(sniExtData[0:2], uint16(1+2+len(nameBytes))) // server name list length
	sniExtData[2] = 0x00 // host_name type
	binary.BigEndian.PutUint16(sniExtData[3:5], uint16(len(nameBytes)))
	copy(sniExtData[5:], nameBytes)

	// SNI extension header: type(2) + length(2) + data
	sniExt := make([]byte, 4+len(sniExtData))
	binary.BigEndian.PutUint16(sniExt[0:2], 0x0000) // SNI extension type
	binary.BigEndian.PutUint16(sniExt[2:4], uint16(len(sniExtData)))
	copy(sniExt[4:], sniExtData)

	// Extensions block: length(2) + extensions
	extensions := make([]byte, 2+len(sniExt))
	binary.BigEndian.PutUint16(extensions[0:2], uint16(len(sniExt)))
	copy(extensions[2:], sniExt)

	// ClientHello body:
	// client_version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) +
	// cipher_suite(2) + compression_len(1) + compression(1) + extensions
	clientVersion := []byte{0x03, 0x03} // TLS 1.2 in ClientHello body
	random := make([]byte, 32)
	sessionIDLen := []byte{0x00} // no session ID
	cipherSuites := []byte{0x00, 0x02, 0x00, 0x2f} // one cipher suite TLS_RSA_WITH_AES_128_CBC_SHA
	compression := []byte{0x01, 0x00} // one compression method (null)

	body := make([]byte, 0)
	body = append(body, clientVersion...)
	body = append(body, random...)
	body = append(body, sessionIDLen...)
	body = append(body, cipherSuites...)
	body = append(body, compression...)
	body = append(body, extensions...)

	// Handshake header: type(1) + length(3)
	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01 // ClientHello
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	// TLS record header: content_type(1) + version(2) + length(2) + handshake
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16 // Handshake
	record[1] = major
	record[2] = minor
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record
}

func TestParseTLSClientHello(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		major      byte
		minor      byte
		wantSNI    string
		wantTLSVer string
	}{
		{
			name:       "tls12_example_com",
			domain:     "example.com",
			major:      0x03,
			minor:      0x03,
			wantSNI:    "example.com",
			wantTLSVer: "TLS 1.2",
		},
		{
			name:       "tls13_long_domain",
			domain:     "very.long.subdomain.example.org",
			major:      0x03,
			minor:      0x04,
			wantSNI:    "very.long.subdomain.example.org",
			wantTLSVer: "TLS 1.3",
		},
		{
			name:       "tls10",
			domain:     "old.example.com",
			major:      0x03,
			minor:      0x01,
			wantSNI:    "old.example.com",
			wantTLSVer: "TLS 1.0",
		},
		{
			name:       "tls11",
			domain:     "test.example.com",
			major:      0x03,
			minor:      0x02,
			wantSNI:    "test.example.com",
			wantTLSVer: "TLS 1.1",
		},
		{
			name:       "ssl30",
			domain:     "legacy.example.com",
			major:      0x03,
			minor:      0x00,
			wantSNI:    "legacy.example.com",
			wantTLSVer: "SSL 3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildClientHello(tt.domain, tt.major, tt.minor)
			sni, tlsVer := parseTLSClientHello(data)
			if sni != tt.wantSNI {
				t.Errorf("SNI: got %q, want %q", sni, tt.wantSNI)
			}
			if tlsVer != tt.wantTLSVer {
				t.Errorf("TLS version: got %q, want %q", tlsVer, tt.wantTLSVer)
			}
		})
	}
}

func TestParseTLSClientHelloMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too_short", []byte{0x16, 0x03, 0x03}},
		{"not_handshake", []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}},
		{"truncated_record", []byte{0x16, 0x03, 0x03, 0x00, 0xFF, 0x01}}, // claims 255 bytes but only has 1
		{"not_client_hello", func() []byte {
			// Build a valid TLS record but with ServerHello (type 0x02) instead.
			data := make([]byte, 10)
			data[0] = 0x16 // handshake
			data[1] = 0x03
			data[2] = 0x03
			binary.BigEndian.PutUint16(data[3:5], 5) // record length = 5
			data[5] = 0x02 // ServerHello, not ClientHello
			return data
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni, _ := parseTLSClientHello(tt.data)
			if sni != "" {
				t.Errorf("expected empty SNI for malformed input, got %q", sni)
			}
		})
	}
}

func TestParseTLSClientHelloNoSNI(t *testing.T) {
	// Build a ClientHello without SNI extension (use a non-SNI extension instead).
	// Extensions block with a single non-SNI extension (type 0x000d = signature_algorithms).
	extData := []byte{0x04, 0x03, 0x05, 0x03} // some signature algorithms
	ext := make([]byte, 4+len(extData))
	binary.BigEndian.PutUint16(ext[0:2], 0x000d) // signature_algorithms
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(extData)))
	copy(ext[4:], extData)

	extensions := make([]byte, 2+len(ext))
	binary.BigEndian.PutUint16(extensions[0:2], uint16(len(ext)))
	copy(extensions[2:], ext)

	clientVersion := []byte{0x03, 0x03}
	random := make([]byte, 32)
	sessionIDLen := []byte{0x00}
	cipherSuites := []byte{0x00, 0x02, 0x00, 0x2f}
	compression := []byte{0x01, 0x00}

	body := make([]byte, 0)
	body = append(body, clientVersion...)
	body = append(body, random...)
	body = append(body, sessionIDLen...)
	body = append(body, cipherSuites...)
	body = append(body, compression...)
	body = append(body, extensions...)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	sni, tlsVer := parseTLSClientHello(record)
	if sni != "" {
		t.Errorf("expected empty SNI when no SNI extension, got %q", sni)
	}
	if tlsVer != "TLS 1.2" {
		t.Errorf("expected TLS version 'TLS 1.2', got %q", tlsVer)
	}
}

func TestHtons(t *testing.T) {
	tests := []struct {
		input uint16
		want  uint16
	}{
		{0x0003, 0x0300},
		{0x0800, 0x0008},
		{0xFFFF, 0xFFFF},
		{0x0000, 0x0000},
	}

	for _, tt := range tests {
		got := htons(tt.input)
		if got != tt.want {
			t.Errorf("htons(0x%04X): got 0x%04X, want 0x%04X", tt.input, got, tt.want)
		}
	}
}
