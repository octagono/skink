package mnemonicode

import (
	"bytes"
	"testing"
)

// --- FUZZ TESTS ---

// FuzzEncode ensures encoder doesn't panic on any byte slice and
// produces the expected number of words.
func FuzzEncode(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x01, 0x02, 0x03, 0x04},
		bytes.Repeat([]byte{0xAB}, 16),
		bytes.Repeat([]byte{0x00}, 100),
		{0xDE, 0xAD, 0xBE, 0xEF},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		words := EncodeWordList(nil, data)

		// Word count must match WordsRequired
		expected := WordsRequired(len(data))
		if len(words) != expected {
			t.Errorf("word count: got %d, want %d for %d bytes",
				len(words), expected, len(data))
		}

		// Every word must be a valid index into WordList
		for i, w := range words {
			if w == "" {
				t.Errorf("word %d is empty", i)
			}
			found := false
			for _, valid := range WordList {
				if w == valid {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("word %d %q not in WordList", i, w)
			}
		}
	})
}

// FuzzEncodeConsistency ensures encoding is deterministic — same input
// always produces same output.
func FuzzEncodeConsistency(f *testing.F) {
	seeds := [][]byte{
		{0x01, 0x02},
		{0xFF, 0xEE, 0xDD},
		bytes.Repeat([]byte{0x42}, 8),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		w1 := EncodeWordList(nil, data)
		w2 := EncodeWordList(nil, data)

		if len(w1) != len(w2) {
			t.Fatalf("non-deterministic length: %d vs %d", len(w1), len(w2))
		}
		for i := range w1 {
			if w1[i] != w2[i] {
				t.Fatalf("non-deterministic word at %d: %q vs %q", i, w1[i], w2[i])
			}
		}
	})
}

// BenchmarkEncode measures encoding throughput.
func BenchmarkEncode(b *testing.B) {
	data := bytes.Repeat([]byte{0xAB}, 32)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeWordList(nil, data)
	}
}
