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
				[]byte{98, 1, 9, 0},
				[]byte{9, 0, 5, 4},
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
	var bufSizes = []int{0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 257, 1023, 1024}
	type testCase struct {
		buf      []byte
		initial  uint16
		csumOrig uint16
		csumNew  uint16
	}
	testCases := make([]testCase, 100000)
	// Ensure same buffer generation for test consistency.
	rnd := rand.New(rand.NewSource(42))
	for i := range testCases {
		testCases[i].buf = make([]byte, bufSizes[i%len(bufSizes)])
		testCases[i].initial = uint16(rnd.Intn(65536))
		rnd.Read(testCases[i].buf)
	}

	for i := range testCases {
		testCases[i].csumOrig = Old(testCases[i].buf, testCases[i].initial)
		testCases[i].csumNew = Checksum(testCases[i].buf, testCases[i].initial)
		if got, want := testCases[i].csumNew, testCases[i].csumOrig; got != want {
			t.Fatalf("new checksum for (buf = %x, initial = %d) does not match old got: %d, want: %d", testCases[i].buf, testCases[i].initial, got, want)
		}
	}
}

func BenchmarkChecksum(b *testing.B) {
	var bufSizes = []int{64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32767, 32768, 65535, 65536}

	checkSumImpls := []struct {
		fn   func([]byte, uint16) uint16
		name string
	}{
		{Old, fmt.Sprintf("checksum_old")},
		{Checksum, fmt.Sprintf("checksum")},
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
