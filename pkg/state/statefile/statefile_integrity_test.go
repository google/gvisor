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

package statefile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
)

// These tests attack the data section of a statefile. The attacks change only
// the chunk structure. The attacks do not use the key.

// splitStatefile divides a statefile into the header and the data section.
func splitStatefile(t *testing.T, sf []byte, keyed bool) (header, data []byte) {
	t.Helper()
	off := len(magicHeader)
	metadataLen := int(binary.BigEndian.Uint64(sf[off : off+8]))
	off += 8 + metadataLen
	if keyed {
		off += sha256.Size
	}
	return sf[:off], sf[off:]
}

// unframeChunks joins the payloads of a keyed data section. It removes the
// hash of each chunk.
func unframeChunks(t *testing.T, data []byte) []byte {
	t.Helper()
	var plain []byte
	for off := 0; off < len(data); {
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n+sha256.Size > len(data) {
			t.Fatalf("truncated chunk at %d", off)
		}
		plain = append(plain, data[off:off+n]...)
		off += n + sha256.Size
	}
	return plain
}

func writeStatefile(t *testing.T, key, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, key, CompressionLevelNone.ToMetadata())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// readStatefile does the same steps as a restore. It reads the number of bytes
// that the writer wrote, then it calls Verify.
func readStatefile(t *testing.T, key, sf []byte, want int) ([]byte, error) {
	t.Helper()
	r, _, err := NewReader(io.NopCloser(bytes.NewReader(sf)), key)
	if err != nil {
		return nil, err
	}
	got := make([]byte, want)
	if _, err := io.ReadFull(r, got); err != nil {
		return nil, err
	}
	return got, r.Verify()
}

// TestReframedDataSectionIsRejected makes sure that a keyed restore rejects a
// data section that an attacker divided into one chunk with a wrong hash.
func TestReframedDataSectionIsRejected(t *testing.T) {
	key, err := randomKey()
	if err != nil {
		t.Fatalf("randomKey: %v", err)
	}
	data := make([]byte, 3*1024*1024)
	for i := range data {
		data[i] = byte(i)
	}
	sf := writeStatefile(t, key, data)

	// A correct statefile must read back and verify.
	if got, err := readStatefile(t, key, sf, len(data)); err != nil {
		t.Fatalf("clean statefile: %v", err)
	} else if !bytes.Equal(got, data) {
		t.Fatalf("clean statefile: data mismatch")
	}

	header, section := splitStatefile(t, sf, true)
	plain := unframeChunks(t, section)
	if !bytes.Equal(plain, data) {
		t.Fatalf("unframed %d bytes, want %d", len(plain), len(data))
	}
	plain[len(plain)/2] ^= 0xFF // Change the data.

	var attacked bytes.Buffer
	attacked.Write(header)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(plain)))
	attacked.Write(hdr[:])
	attacked.Write(plain)
	attacked.Write(bytes.Repeat([]byte{0xAA}, sha256.Size)) // Wrong hash.

	if _, err := readStatefile(t, key, attacked.Bytes(), len(data)); err == nil {
		t.Errorf("keyed restore accepted a re-framed, tampered statefile")
	}
}

// TestUnhashedDataSectionIsRejected makes sure that a keyed restore rejects a
// chunk that is larger than the data that the restore reads.
func TestUnhashedDataSectionIsRejected(t *testing.T) {
	key, err := randomKey()
	if err != nil {
		t.Fatalf("randomKey: %v", err)
	}
	data := make([]byte, 64*1024)
	sf := writeStatefile(t, key, data)
	header, section := splitStatefile(t, sf, true)
	plain := unframeChunks(t, section)

	var attacked bytes.Buffer
	attacked.Write(header)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(plain))+4096)
	attacked.Write(hdr[:])
	attacked.Write(plain)
	// There is no hash. The restore stops before the end of the chunk.

	if _, err := readStatefile(t, key, attacked.Bytes(), len(data)); err == nil {
		t.Errorf("keyed restore accepted a statefile whose data was never hash-checked")
	}
}
