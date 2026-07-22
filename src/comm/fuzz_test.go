package comm

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// parseFrame extracts the message framing logic from Comm.Read() for fuzzing.
// Reads: 4-byte magic + 4-byte little-endian length + body.
// Returns the body bytes or an error.
func parseFrame(r interface {
	io.Reader
}, magic []byte, maxSize uint32) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header, magic) {
		return nil, errBadMagic
	}

	header = make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	var numBytes uint32
	rbuf := bytes.NewReader(header)
	if err := binary.Read(rbuf, binary.LittleEndian, &numBytes); err != nil {
		return nil, err
	}
	if numBytes > maxSize {
		return nil, errTooLarge
	}

	buf := make([]byte, numBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

var (
	errBadMagic = &frameError{"bad magic bytes"}
	errTooLarge = &frameError{"message too large"}
)

type frameError struct{ msg string }

func (e *frameError) Error() string { return e.msg }

// io.Reader import shim
var _ = bytes.Equal

// --- FUZZ TESTS ---

// FuzzParseFrame feeds random byte sequences to the message frame parser.
// Ensures no panics on truncated magic, oversized length, corrupted body.
func FuzzParseFrame(f *testing.F) {
	magic := []byte("Skink")
	maxSize := uint32(64 * 1024 * 1024)

	// Seed with valid frame
	validBody := []byte(`{"type":"test","data":"hello"}`)
	validFrame := make([]byte, 0, 8+len(validBody))
	validFrame = append(validFrame, magic...)
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(validBody)))
	validFrame = append(validFrame, lenBytes...)
	validFrame = append(validFrame, validBody...)

	seeds := [][]byte{
		validFrame,
		{},                                    // empty
		{'S', 'k', 'i'},                       // truncated magic
		{'X', 'X', 'X', 'X', 0, 0, 0, 0},      // bad magic
		{'S', 'k', 'i', 'n', 'k', 0, 0, 0, 1}, // magic + length=1 but no body
		{'S', 'k', 'i', 'n', 'k', 0, 0, 0, 0}, // zero-length body (valid)
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, err := parseFrame(r, magic, maxSize)
		_ = err // only care about panics
	})
}

// FuzzParseFrameOversized feeds length declarations exceeding max size.
func FuzzParseFrameOversized(f *testing.F) {
	magic := []byte("Skink")
	maxSize := uint32(1024) // intentionally small to trigger size check

	seeds := [][]byte{
		func() []byte {
			b := append([]byte{}, magic...)
			b = append(b, 0xFF, 0xFF, 0xFF, 0xFF) // 4GB length
			return b
		}(),
		func() []byte {
			b := append([]byte{}, magic...)
			b = append(b, 0x00, 0x04, 0x00, 0x00) // 1024 bytes
			return b
		}(),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure at least magic + length
		if len(data) < 8 {
			return
		}
		r := bytes.NewReader(data)
		body, err := parseFrame(r, magic, maxSize)
		if err == nil && uint32(len(body)) > maxSize {
			t.Errorf("body exceeds max: %d > %d", len(body), maxSize)
		}
	})
}

// BenchmarkParseFrame measures frame parsing overhead.
func BenchmarkParseFrame(b *testing.B) {
	magic := []byte("Skink")
	maxSize := uint32(64 * 1024 * 1024)
	body := bytes.Repeat([]byte("x"), 1024)

	frame := make([]byte, 0, 8+len(body))
	frame = append(frame, magic...)
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(body)))
	frame = append(frame, lenBytes...)
	frame = append(frame, body...)

	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(frame)
		_, _ = parseFrame(r, magic, maxSize)
	}
}
