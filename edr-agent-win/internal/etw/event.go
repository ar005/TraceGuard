// event.go — raw property parsers for ETW event UserData payloads.
// No OS-specific imports; compiles and tests on all platforms.
package etw

import (
	"encoding/binary"
	"net"
)

// ReadUint32 reads a little-endian uint32 from data at offset.
// Returns (value, offset+4). Returns (0, offset) if data is too short.
func ReadUint32(data []byte, offset int) (uint32, int) {
	if offset+4 > len(data) {
		return 0, offset
	}
	return binary.LittleEndian.Uint32(data[offset:]), offset + 4
}

// ReadUint64 reads a little-endian uint64 from data at offset.
func ReadUint64(data []byte, offset int) (uint64, int) {
	if offset+8 > len(data) {
		return 0, offset
	}
	return binary.LittleEndian.Uint64(data[offset:]), offset + 8
}

// ReadUint16 reads a little-endian uint16 from data at offset.
func ReadUint16(data []byte, offset int) (uint16, int) {
	if offset+2 > len(data) {
		return 0, offset
	}
	return binary.LittleEndian.Uint16(data[offset:]), offset + 2
}

// ReadUTF16NullTerminated reads a null-terminated UTF-16LE string from data
// at offset. Returns (string, offset past null terminator).
// Returns ("", offset) if data is too short.
func ReadUTF16NullTerminated(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", offset
	}
	start := offset
	for offset+1 < len(data) {
		if data[offset] == 0 && data[offset+1] == 0 {
			break
		}
		offset += 2
	}
	raw := data[start:offset]
	runes := make([]rune, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		r := rune(raw[i]) | rune(raw[i+1])<<8
		if r != 0 {
			runes = append(runes, r)
		}
	}
	return string(runes), offset + 2 // skip the two null bytes
}

// ReadIPv4 reads 4 bytes as a dotted IPv4 address string.
func ReadIPv4(data []byte, offset int) (string, int) {
	if offset+4 > len(data) {
		return "", offset
	}
	return net.IP(data[offset : offset+4]).String(), offset + 4
}

// ReadIPv6 reads 16 bytes as an IPv6 address string.
func ReadIPv6(data []byte, offset int) (string, int) {
	if offset+16 > len(data) {
		return "", offset
	}
	return net.IP(data[offset : offset+16]).String(), offset + 16
}

// ReadPortBE reads a big-endian (network byte order) uint16 port number.
// ETW kernel-network events encode ports in network byte order.
func ReadPortBE(data []byte, offset int) (uint16, int) {
	if offset+2 > len(data) {
		return 0, offset
	}
	return binary.BigEndian.Uint16(data[offset:]), offset + 2
}

// Skip advances offset by n bytes without reading. Used to skip over
// payload fields that a monitor does not need.
func Skip(offset, n int) int {
	return offset + n
}
