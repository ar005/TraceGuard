// parse.go — TLS ClientHello SNI parser and 30-second dedup window.
// No OS-specific imports; testable on Linux CI without the Windows build tag.
package tlssni

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// parseTLSClientHelloSNI extracts the SNI hostname and TLS version from a raw
// TLS record byte slice.  data must start at the TLS record header (content type
// byte).  Returns ("", "") when the data is not a TLS ClientHello or carries no
// SNI extension.
//
// Note: for TLS 1.3 connections the ClientHello legacy version field reports
// 0x0303 (TLS 1.2); the actual negotiated version lives in the
// supported_versions extension which we do not walk.  The returned tlsVersion
// therefore reads "TLS 1.2" for TLS 1.3 sessions.
func parseTLSClientHelloSNI(data []byte) (sni, tlsVersion string) {
	// TLS record header: content-type(1) + version(2) + length(2) = 5 bytes.
	if len(data) < 5 || data[0] != 0x16 { // 0x16 = Handshake
		return "", ""
	}
	major, minor := data[1], data[2]
	if major != 3 || minor < 1 || minor > 4 { // TLS 1.0–1.3 or compat header
		return "", ""
	}

	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return "", ""
	}

	hs := data[5 : 5+recLen]

	// Handshake header: type(1) + length(3).
	if len(hs) < 4 || hs[0] != 0x01 { // 0x01 = ClientHello
		return "", ""
	}
	hsBodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsBodyLen {
		return "", ""
	}
	hello := hs[4 : 4+hsBodyLen]

	// ClientHello body layout:
	//   client_version (2)
	//   random         (32)
	//   session_id     (1 length + n bytes)
	//   cipher_suites  (2 length + n bytes)
	//   compression    (1 length + n bytes)
	//   extensions     (2 length + n bytes)  [optional]
	if len(hello) < 35 {
		return "", ""
	}
	tlsVersion = tlsVersionString(hello[0], hello[1])

	pos := 34 // skip version(2) + random(32)

	// Session ID.
	sidLen := int(hello[pos])
	pos++
	pos += sidLen

	// Cipher suites.
	if pos+2 > len(hello) {
		return "", tlsVersion
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + csLen

	// Compression methods.
	if pos+1 > len(hello) {
		return "", tlsVersion
	}
	compLen := int(hello[pos])
	pos += 1 + compLen

	// Extensions block.
	if pos+2 > len(hello) {
		return "", tlsVersion
	}
	extsLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if pos+extsLen > len(hello) {
		extsLen = len(hello) - pos
	}
	exts := hello[pos : pos+extsLen]

	// Walk extensions looking for type 0x0000 (server_name).
	extPos := 0
	for extPos+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[extPos : extPos+2])
		extDataLen := int(binary.BigEndian.Uint16(exts[extPos+2 : extPos+4]))
		extPos += 4
		if extPos+extDataLen > len(exts) {
			break
		}
		if extType == 0x0000 { // server_name
			sni = parseSNIExtension(exts[extPos : extPos+extDataLen])
			return sni, tlsVersion
		}
		extPos += extDataLen
	}
	return "", tlsVersion
}

// parseSNIExtension extracts the hostname from the server_name extension data
// (the bytes after the extension type and length fields).
func parseSNIExtension(data []byte) string {
	// server_name_list_len (2) | server_name_type (1) | server_name_len (2) | name
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen < 3 || len(data) < 2+listLen {
		return ""
	}
	if data[2] != 0x00 { // host_name = 0
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if nameLen == 0 || len(data) < 5+nameLen {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// tlsVersionString converts the two-byte legacy version field from a
// ClientHello into a human-readable TLS version string.
func tlsVersionString(major, minor byte) string {
	switch {
	case major == 3 && minor == 1:
		return "TLS 1.0"
	case major == 3 && minor == 2:
		return "TLS 1.1"
	case major == 3 && minor == 3:
		return "TLS 1.2"
	case major == 3 && minor == 4:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS %d.%d", int(major)-2, int(minor))
	}
}

// ── Deduplicator ─────────────────────────────────────────────────────────────

// deduper suppresses repeated SNI events for the same source IP + hostname
// within a 30-second sliding window.
type deduper struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newDeduper() deduper {
	return deduper{entries: make(map[string]time.Time)}
}

// seen returns true if key was already reported within the last 30 seconds,
// and records it (or refreshes it) otherwise.
func (d *deduper) seen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	// Periodic GC: sweep expired entries when the map grows large.
	if len(d.entries) > 5000 {
		for k, exp := range d.entries {
			if !exp.After(now) {
				delete(d.entries, k)
			}
		}
	}
	if exp, ok := d.entries[key]; ok && exp.After(now) {
		return true
	}
	d.entries[key] = now.Add(30 * time.Second)
	return false
}
