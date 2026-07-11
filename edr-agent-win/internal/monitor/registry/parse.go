// parse.go — platform-independent registry payload parser and path helpers.
// No OS-specific imports; testable on Linux CI without the Windows build tag.
package registry

import "strings"

// regPayloadHeaderSize is the number of bytes to skip at the start of a
// Microsoft-Windows-Kernel-Registry ETW event payload before the key path.
//
//	Layout: InitialTime(8) + Status(4) + Index(4) + KeyObject(8) = 24 bytes
const regPayloadHeaderSize = 24

// parseRegPayload extracts the key path and (for SetValue/DeleteValue) the
// value name from a Kernel-Registry ETW event payload.
//
// Returns ok=false when the payload is too short or the key path is empty.
// valueName is non-empty only for event IDs 1 (SetValue) and 2 (DeleteValue).
func parseRegPayload(eventID uint16, data []byte) (keyPath, valueName string, ok bool) {
	if len(data) < regPayloadHeaderSize {
		return "", "", false
	}
	keyPath, offset := readUTF16Null(data, regPayloadHeaderSize)
	if keyPath == "" {
		return "", "", false
	}
	if eventID == 1 || eventID == 2 { // SetValueKey or DeleteValueKey
		valueName, _ = readUTF16Null(data, offset)
	}
	return keyPath, valueName, true
}

// readUTF16Null reads a null-terminated UTF-16LE string from data starting
// at offset. Returns (decoded string, offset past the two-byte null terminator).
// Returns ("", offset) if offset is past the end of data.
func readUTF16Null(data []byte, offset int) (string, int) {
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
		r := rune(uint16(raw[i]) | uint16(raw[i+1])<<8)
		runes = append(runes, r)
	}
	return string(runes), offset + 2
}

// regNTPathToWin32 converts an NT object-manager registry path to Win32 form.
//
//	\REGISTRY\MACHINE\Foo  →  HKLM\Foo
//	\REGISTRY\USER\<SID>\Bar  →  HKCU\Bar   (SID is stripped)
//
// Unrecognised paths are returned unchanged.
func regNTPathToWin32(ntPath string) string {
	const (
		ntMachine = `\REGISTRY\MACHINE\`
		ntUser    = `\REGISTRY\USER\`
	)
	switch {
	case strings.HasPrefix(ntPath, ntMachine):
		return `HKLM\` + ntPath[len(ntMachine):]
	case strings.HasPrefix(ntPath, ntUser):
		rest := ntPath[len(ntUser):]
		if idx := strings.IndexByte(rest, '\\'); idx >= 0 {
			return `HKCU\` + rest[idx+1:]
		}
		return `HKCU\` + rest
	default:
		return ntPath
	}
}
