// Copyright 2019 The gVisor Authors.
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

// Package header provides the implementation of the encoding and decoding of
// network protocol headers.
package checksum

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func TestChecksumer(t *testing.T) {
	testCases := []struct {
		name string
		data [][]byte
		want uint16
	}{
		{
			name: "empty",
			want: 0,
		},
		{
			name: "OneOddView",
			data: [][]byte{
				{1, 9, 0, 5, 4},
			},
			want: 1294,
		},
		{
			name: "TwoOddViews",
			data: [][]byte{
				{1, 9, 0, 5, 4},
				{4, 3, 7, 1, 2, 123},
			},
			want: 33819,
		},
		{
			name: "OneEvenView",
			data: [][]byte{
				{1, 9, 0, 5},
			},
			want: 270,
		},
		{
			name: "TwoEvenViews",
			data: [][]byte{
				{98, 1, 9, 0},
				{9, 0, 5, 4},
			},
			want: 30981,
		},
		{
			name: "ThreeViews",
			data: [][]byte{
				{77, 11, 33, 0, 55, 44},
				{98, 1, 9, 0, 5, 4},
				{4, 3, 7, 1, 2, 123, 99},
			},
			want: 34236,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var all bytes.Buffer
			var c Checksumer
			for _, b := range tc.data {
				c.Add(b)
				// Append to the buffer. We will check the checksum as a whole later.
				if _, err := all.Write(b); err != nil {
					t.Fatalf("all.Write(b) = _, %s; want _, nil", err)
				}
			}
			if got, want := c.Checksum(), tc.want; got != want {
				t.Errorf("c.Checksum() = %d, want %d", got, want)
			}
			if got, want := Checksum(all.Bytes(), 0 /* initial */), tc.want; got != want {
				t.Errorf("Checksum(flatten tc.data) = %d, want %d", got, want)
			}
		})
	}
}

func TestChecksum(t *testing.T) {
	var bufSizes = []int{
		0,
		1,
		2,
		3,
		4,
		7,
		8,
		15,
		16,
		31,
		32,
		63,
		64,
		127,
		128,
		255,
		256,
		257,
		1023,
		1024,
	}
	type testCase struct {
		buf     []byte
		initial uint16
	}
	testCases := make([]testCase, 100000)
	// Ensure same buffer generation for test consistency.
	rnd := rand.New(rand.NewSource(42))
	for i := range testCases {
		testCases[i].buf = make([]byte, bufSizes[i%len(bufSizes)])
		testCases[i].initial = uint16(rnd.Intn(65536))
		rnd.Read(testCases[i].buf)
	}

	checkSumImpls := []struct {
		fn   func([]byte, uint16) uint16
		name string
	}{
		{old, "checksum_old"},
		{Checksum, "checksum"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("buf size %d", len(tc.buf)), func(t *testing.T) {
			// Also test different offsets into the buffers. This
			// tests the correctess of optimizations dealing with
			// non-64-bit aligned numbers.
			for offset := 0; offset < 8; offset++ {
				t.Run(fmt.Sprintf("offset %d", offset), func(t *testing.T) {
					if offset > len(tc.buf) {
						t.Skip("offset is greater than buffer size")
					}
					buf := tc.buf[offset:]
					for i := 0; i < len(checkSumImpls)-1; i++ {
						first := checkSumImpls[i].fn(buf, tc.initial)
						second := checkSumImpls[i+1].fn(buf, tc.initial)
						if first != second {
							t.Fatalf("for (buf = 0x%x, initial = 0x%x) checksum %q does not match %q: got: 0x%x and 0x%x", buf, tc.initial, checkSumImpls[i].name, checkSumImpls[i+1].name, first, second)
						}
					}
				})
			}
		})
	}
}

// TestIncrementalChecksum tests for breakages of Checksummer as described in
// b/289284842.
func TestIncrementalChecksum(t *testing.T) {
	buf := []byte{
		0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
		0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
	}

	// Go through buf and check that checksum(buf[:end]) is equivalent to
	// an incremental checksum of two chunks of buf[:end].
	for end := 2; end <= len(buf); end++ {
		for start := 1; start < end; start++ {
			t.Run(fmt.Sprintf("end=%d start=%d", end, start), func(t *testing.T) {
				var cs Checksumer
				cs.Add(buf[:end])
				csum := cs.Checksum()

				cs = Checksumer{}
				cs.Add(buf[:start])
				cs.Add(buf[start:end])
				csumIncremental := cs.Checksum()

				if want := old(buf[:end], 0); csum != want {
					t.Fatalf("checksum is wrong: got %x, expected %x", csum, want)
				}
				if csum != csumIncremental {
					t.Errorf("checksums should be the same: %x %x", csum, csumIncremental)
				}
			})
		}
	}
}

func BenchmarkChecksum(b *testing.B) {
	var bufSizes = []int{64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32767, 32768, 65535, 65536}

	checkSumImpls := []struct {
		fn   func([]byte, uint16) uint16
		name string
	}{
		{old, "checksum_old"},
		{Checksum, "checksum"},
	}

	for _, csumImpl := range checkSumImpls {
		// Ensure same buffer generation for test consistency.
		rnd := rand.New(rand.NewSource(42))
		for _, bufSz := range bufSizes {
			b.Run(fmt.Sprintf("%s_%d", csumImpl.name, bufSz), func(b *testing.B) {
				tc := struct {
					buf     []byte
					initial uint16
					csum    uint16
				}{
					buf:     make([]byte, bufSz),
					initial: uint16(rnd.Intn(65536)),
				}
				rnd.Read(tc.buf)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					tc.csum = csumImpl.fn(tc.buf, tc.initial)
				}
			})
		}
	}
}

// old calculates the checksum (as defined in RFC 1071) of the bytes in
// the given byte array. This function uses a non-optimized implementation. Its
// only retained for reference and to use as a benchmark/test. Most code should
// use the header.Checksum function.
//
// The initial checksum must have been computed on an even number of bytes.
func old(buf []byte, initial uint16) uint16 {
	s, _ := oldCalculateChecksum(buf, false, uint32(initial))
	return s
}

func oldCalculateChecksum(buf []byte, odd bool, initial uint32) (uint16, bool) {
	v := initial

	if odd {
		v += uint32(buf[0])
		buf = buf[1:]
	}

	l := len(buf)
	odd = l&1 != 0
	if odd {
		l--
		v += uint32(buf[l]) << 8
	}

	for i := 0; i < l; i += 2 {
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
	}

	return Combine(uint16(v), uint16(v>>16)), odd
}
