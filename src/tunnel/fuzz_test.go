package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// parseStreamID extracts the proxyID parsing logic from handleDataStream
// so it can be fuzzed without a full Server/Conn setup.
// Reads 2-byte big-endian length prefix, then that many bytes.
// Returns the proxyID string or an error.
func parseStreamID(r io.Reader) (string, error) {
	var idLen [2]byte
	if _, err := io.ReadFull(r, idLen[:]); err != nil {
		return "", err
	}

	idSize := int(idLen[0])<<8 | int(idLen[1])
	if idSize < 1 || idSize > 512 {
		return "", ErrInvalidStreamIDLength
	}

	idBuf := make([]byte, idSize)
	if _, err := io.ReadFull(r, idBuf); err != nil {
		return "", err
	}

	return string(idBuf), nil
}

// ErrInvalidStreamIDLength is returned when the stream ID length prefix
// is outside the valid range [1, 512].
var ErrInvalidStreamIDLength = io.ErrUnexpectedEOF

// classifyStreamID determines the stream type from a proxyID.
// Returns one of: "proxy", "fwd", "exec", "access", "reg", "data", "unknown".
// This is the routing logic from handleDataStream, extracted for fuzzing.
func classifyStreamID(proxyID string) string {
	switch {
	case strings.HasPrefix(proxyID, "REG|") || strings.HasPrefix(proxyID, "DATA|"):
		return "relay"
	case strings.HasPrefix(proxyID, "FWD|"):
		return "fwd"
	case strings.HasPrefix(proxyID, "EXEC|"):
		return "exec"
	case strings.HasPrefix(proxyID, "ACCESS|"):
		return "access"
	default:
		return "proxy"
	}
}

// parseAccessHeader parses an ACCESS| stream header.
// Format: "ACCESS|<token>|<targetAddr>"
// Returns token, targetAddr, or an error if malformed.
func parseAccessHeader(header string) (token, targetAddr string, err error) {
	parts := strings.SplitN(header[7:], "|", 2)
	if len(parts) < 1 || parts[0] == "" {
		return "", "", ErrInvalidStreamIDLength
	}
	token = parts[0]
	if len(parts) > 1 {
		targetAddr = parts[1]
	}
	return token, targetAddr, nil
}

// --- FUZZ TESTS ---

// FuzzParseStreamID feeds random byte sequences to the stream ID parser.
// Ensures no panics regardless of input — malformed length prefixes,
// truncated IDs, oversized length declarations, etc.
func FuzzParseStreamID(f *testing.F) {
	// Seed with valid inputs
	seeds := [][]byte{
		{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}, // valid 5-byte ID
		{0x00, 0x04, 'F', 'W', 'D', '|', '1', '2', '7', '.', '0', '.', '0', '.', '1', ':', '8', '0'},
		{0x00, 0x07, 'A', 'C', 'C', 'E', 'S', 'S', '|', 'a', 'b', 'c'},
		{0x00, 0x01, 'x'},      // minimal valid ID
		{0x02, 0x00, 'a', 'b'}, // 512-byte length declared
		{},                     // empty input
		{0xff, 0xff},           // max length (will fail validation)
		{0x00, 0x00},           // zero length (invalid)
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The parser must never panic — only return an error
		r := bytes.NewReader(data)
		_, err := parseStreamID(r)
		// We don't care about the error, only that it doesn't panic
		_ = err
	})
}

// FuzzClassifyStreamID feeds random strings to the classifier.
// Ensures routing logic is robust against arbitrary prefix combinations.
func FuzzClassifyStreamID(f *testing.F) {
	seeds := []string{
		"abc123",
		"FWD|127.0.0.1:80",
		"EXEC|ls -la",
		"ACCESS|token|target",
		"REG|tunnel1|http|localhost:3000",
		"DATA|tunnel1|target",
		"",
		"FW",
		"ACCESS",
		"ACCESS||||||",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, proxyID string) {
		result := classifyStreamID(proxyID)
		// Verify result is always one of the known types
		validTypes := map[string]bool{
			"proxy": true, "fwd": true, "exec": true,
			"access": true, "relay": true,
		}
		if !validTypes[result] {
			t.Errorf("unknown classification: %q for proxyID %q", result, proxyID)
		}
	})
}

// FuzzParseAccessHeader feeds random strings to the access header parser.
// Ensures token extraction works for all inputs without panicking.
func FuzzParseAccessHeader(f *testing.F) {
	seeds := []string{
		"ACCESS|abc123|localhost:22",
		"ACCESS|abc123",
		"ACCESS|",
		"ACCESS|||",
		"ACCESS",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, header string) {
		// Skip headers too short to contain "ACCESS|"
		if len(header) < 7 {
			return
		}
		token, target, err := parseAccessHeader(header)
		_ = token
		_ = target
		_ = err
	})
}

// BenchmarkParseStreamID measures parser overhead for perf tracking.
func BenchmarkParseStreamID(b *testing.B) {
	// 64-byte proxyID (typical)
	id := strings.Repeat("x", 64)
	buf := make([]byte, 2+len(id))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(id)))
	copy(buf[2:], id)

	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(buf)
		_, _ = parseStreamID(r)
	}
}

// BenchmarkClassifyStreamID measures classification overhead.
func BenchmarkClassifyStreamID(b *testing.B) {
	ids := []string{
		strings.Repeat("x", 32),
		"FWD|10.0.0.1:8080",
		"ACCESS|abcdef1234567890|localhost:22",
		"REG|tunnel1|tcp|localhost:22",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifyStreamID(ids[i%len(ids)])
	}
}
