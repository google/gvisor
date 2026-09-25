// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compressio

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

var integrityKey = []byte("0123456789abcdef0123456789abcdef")

// writeKeyed makes a correct keyed nocompressio stream.
func writeKeyed(t *testing.T, data []byte, chunkSize uint32) []byte {
	t.Helper()
	var out bytes.Buffer
	w := NewSimpleWriter(&out, integrityKey, chunkSize)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.Bytes()
}

// unframe reads a keyed stream and joins the chunk payloads. It needs no key.
func unframe(t *testing.T, stream []byte) []byte {
	t.Helper()
	var plain []byte
	for off := 0; off < len(stream); {
		if off+4 > len(stream) {
			t.Fatalf("truncated chunk header at %d", off)
		}
		n := int(binary.BigEndian.Uint32(stream[off : off+4]))
		off += 4
		if off+n+sha256.Size > len(stream) {
			t.Fatalf("truncated chunk body at %d", off)
		}
		plain = append(plain, stream[off:off+n]...)
		off += n + sha256.Size
	}
	return plain
}

// frame writes payload as one chunk with a wrong hash. It needs no key.
func frame(payload []byte, declaredSize uint32, withHash bool) []byte {
	var out bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], declaredSize)
	out.Write(hdr[:])
	out.Write(payload)
	if withHash {
		out.Write(bytes.Repeat([]byte{0xAA}, sha256.Size))
	}
	return out.Bytes()
}

func testData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}
	return data
}

func newReader(b []byte) *SimpleReader {
	return NewSimpleReader(io.NopCloser(bytes.NewReader(b)), integrityKey)
}

// TestReframedStreamIsRejected makes sure that the reader rejects a stream
// that an attacker divided into one chunk with a wrong hash.
func TestReframedStreamIsRejected(t *testing.T) {
	for _, chunkSize := range []uint32{4096, 1024 * 1024} {
		data := testData(3 * 1024 * 1024)
		plain := unframe(t, writeKeyed(t, data, chunkSize))
		if !bytes.Equal(plain, data) {
			t.Fatalf("unframe mismatch: got %d bytes, want %d", len(plain), len(data))
		}
		plain[len(plain)/2] ^= 0xFF
		attacked := frame(plain, uint32(len(plain)), true)

		r := newReader(attacked)
		got := make([]byte, len(data))
		if n, err := io.ReadFull(r, got); err == nil {
			t.Errorf("chunkSize=%d: io.ReadFull accepted a re-framed, tampered stream (n=%d)", chunkSize, n)
		}
	}
}

// TestReframedStreamIsRejectedSmallReads makes the same test with small reads,
// as state/wire.readFull does.
func TestReframedStreamIsRejectedSmallReads(t *testing.T) {
	data := testData(64 * 1024)
	plain := unframe(t, writeKeyed(t, data, 4096))
	plain[0] ^= 0xFF
	attacked := frame(plain, uint32(len(plain)), true)

	r := newReader(attacked)
	buf := make([]byte, 8)
	read := 0
	for read < len(data) {
		n, err := r.Read(buf)
		read += n
		if n > 0 && err != nil {
			t.Fatalf("Read returned %d bytes together with error %v; callers drop such errors", n, err)
		}
		if err != nil {
			return // Rejected, as expected.
		}
	}
	t.Errorf("wire-style reader consumed %d tampered bytes with no fatal error", read)
}

// TestOversizedChunkIsRejected makes sure that Verify rejects a chunk that is
// larger than the data that the caller reads.
func TestOversizedChunkIsRejected(t *testing.T) {
	data := testData(64 * 1024)
	plain := unframe(t, writeKeyed(t, data, 4096))
	plain[0] ^= 0xFF
	// Declare a chunk much larger than what is actually supplied, and omit
	// the trailing hash entirely.
	attacked := frame(plain, uint32(len(plain))+1024, false)

	r := newReader(attacked)
	got := make([]byte, len(data))
	if _, err := io.ReadFull(r, got); err != nil {
		return // Rejected during read.
	}
	if err := r.Verify(); err == nil {
		t.Errorf("Verify accepted a stream whose data was never hash-checked")
	}
}

// TestTruncatedStreamIsRejected makes sure that Verify rejects a stream with
// missing chunks at the end.
func TestTruncatedStreamIsRejected(t *testing.T) {
	data := testData(64 * 1024)
	stream := writeKeyed(t, data, 4096)
	// Drop the last chunk (4096 bytes of data + header + hash).
	truncated := stream[:len(stream)-(4+4096+sha256.Size)]

	r := newReader(truncated)
	got := make([]byte, len(data))
	if _, err := io.ReadFull(r, got); err != nil {
		return // Rejected during read.
	}
	if err := r.Verify(); err == nil {
		t.Errorf("Verify accepted a truncated stream")
	}
}

// TestTrailingDataIsRejected makes sure that Verify rejects added chunks.
func TestTrailingDataIsRejected(t *testing.T) {
	data := testData(8192)
	stream := writeKeyed(t, data, 4096)
	stream = append(stream, frame([]byte("evil"), 4, true)...)

	r := newReader(stream)
	got := make([]byte, len(data))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if err := r.Verify(); err == nil {
		t.Errorf("Verify accepted a stream with trailing data")
	}
}

// TestStickyErrorAfterMismatch makes sure that the reader gives no more data
// after the hashes do not agree.
func TestStickyErrorAfterMismatch(t *testing.T) {
	data := testData(8192)
	plain := unframe(t, writeKeyed(t, data, 4096))
	attacked := frame(plain, uint32(len(plain)), true)

	r := newReader(attacked)
	if _, err := io.ReadFull(r, make([]byte, len(data))); err == nil {
		t.Fatalf("re-framed stream accepted")
	}
	for i := 0; i < 3; i++ {
		n, err := r.Read(make([]byte, 16))
		if err == nil || n != 0 {
			t.Errorf("read %d after fatal error: n=%d err=%v", i, n, err)
		}
	}
}

// TestInPlaceTamperIsRejected changes one byte at different positions,
// including the last byte of the stream.
func TestInPlaceTamperIsRejected(t *testing.T) {
	data := testData(8192)
	stream := writeKeyed(t, data, 4096)
	for _, pos := range []int{0, 4, 100, len(stream) / 2, len(stream) - sha256.Size, len(stream) - 1} {
		tampered := append([]byte(nil), stream...)
		tampered[pos] ^= 0xFF

		r := newReader(tampered)
		got := make([]byte, len(data))
		_, err := io.ReadFull(r, got)
		if err == nil {
			err = r.Verify()
		}
		if err == nil {
			t.Errorf("tampering at offset %d was accepted", pos)
		}
	}
}

// TestGoodStreamVerifies makes sure that a correct stream reads back, for small
// chunks and for large chunks.
func TestGoodStreamVerifies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		chunkSize uint32
	}{
		{"buffered", 3 * 1024 * 1024, 1024 * 1024},
		{"tiny", 1, 1},
		{"oversized-direct-write", 4 * maxVerifiedChunkSize, 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := testData(tc.size)
			r := newReader(writeKeyed(t, data, tc.chunkSize))
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(data))
			}
			if err := r.Verify(); err != nil {
				t.Errorf("Verify on a good stream: %v", err)
			}
		})
	}
}

// TestVerifyWithoutKeyIsNoop makes sure that a stream with no key still reads
// back.
func TestVerifyWithoutKeyIsNoop(t *testing.T) {
	data := testData(4096)
	var out bytes.Buffer
	w := NewSimpleWriter(&out, nil, 1024)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := NewSimpleReader(io.NopCloser(bytes.NewReader(out.Bytes())), nil)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch")
	}
	if err := r.Verify(); err != nil {
		t.Errorf("Verify without key: %v", err)
	}
}

// TestHugeDeclaredChunkDoesNotAllocate makes sure that a very large chunk size
// in the stream does not make a very large allocation.
func TestHugeDeclaredChunkDoesNotAllocate(t *testing.T) {
	attacked := frame([]byte("short"), 0xFFFFFFFF, false)
	r := newReader(attacked)
	if _, err := io.ReadFull(r, make([]byte, 64)); err == nil {
		t.Errorf("reader accepted a chunk declaring 4GiB of data")
	}
}

// TestVerifyGivesReadError makes sure that Verify gives the error that Read
// gave in a large chunk.
func TestVerifyGivesReadError(t *testing.T) {
	// A write larger than chunkSize makes one chunk of 3 MiB.
	data := testData(3 * maxVerifiedChunkSize)
	stream := writeKeyed(t, data, 1024)

	for _, tc := range []struct {
		name   string
		stream []byte
		want   error
	}{
		{
			name: "hash-mismatch",
			stream: func() []byte {
				s := append([]byte(nil), stream...)
				s[4+len(data)/2] ^= 0xFF
				return s
			}(),
			want: ErrHashMismatch,
		},
		{
			name:   "truncated",
			stream: stream[:4+len(data)/2],
			want:   io.ErrUnexpectedEOF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReader(tc.stream)
			if _, err := io.ReadAll(r); !errors.Is(err, tc.want) {
				t.Fatalf("ReadAll: got %v, want %v", err, tc.want)
			}
			if err := r.Verify(); !errors.Is(err, tc.want) {
				t.Errorf("Verify: got %v, want %v", err, tc.want)
			}
		})
	}
}
