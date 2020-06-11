// Copyright 2020 The gVisor Authors.
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

package merkletree

import (
	"bytes"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/usermem"
)

func TestSize(t *testing.T) {
	testCases := []struct {
		dataSize           int64
		expectedLevelStart []int64
	}{
		{
			dataSize:           100,
			expectedLevelStart: []int64{0},
		},
		{
			dataSize:           1000000,
			expectedLevelStart: []int64{0, 2, 3},
		},
		{
			dataSize:           4096 * int64(usermem.PageSize),
			expectedLevelStart: []int64{0, 32, 33},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			s := MakeSize(tc.dataSize)
			if s.blockSize != int64(usermem.PageSize) {
				t.Errorf("got blockSize %d, want %d", s.blockSize, usermem.PageSize)
			}
			if s.digestSize != sha256DigestSize {
				t.Errorf("got digestSize %d, want %d", s.digestSize, sha256DigestSize)
			}
			if len(s.levelStart) != len(tc.expectedLevelStart) {
				t.Errorf("got levels %d, want %d", len(s.levelStart), len(tc.expectedLevelStart))
			}
			for i := 0; i < len(s.levelStart) && i < len(tc.expectedLevelStart); i++ {
				if s.levelStart[i] != tc.expectedLevelStart[i] {
					t.Errorf("got levelStart[%d] %d, want %d", i, s.levelStart[i], tc.expectedLevelStart[i])
				}
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	// The input data has size dataSize. It starts with the data in startWith,
	// and all other bytes are zeroes.
	testCases := []struct {
		dataSize     int
		startWith    []byte
		expectedRoot []byte
	}{
		{
			dataSize:     usermem.PageSize,
			startWith:    nil,
			expectedRoot: []byte{173, 127, 172, 178, 88, 111, 198, 233, 102, 192, 4, 215, 209, 209, 107, 2, 79, 88, 5, 255, 124, 180, 124, 122, 133, 218, 189, 139, 72, 137, 44, 167},
		},
		{
			dataSize:     128*usermem.PageSize + 1,
			startWith:    nil,
			expectedRoot: []byte{62, 93, 40, 92, 161, 241, 30, 223, 202, 99, 39, 2, 132, 113, 240, 139, 117, 99, 79, 243, 54, 18, 100, 184, 141, 121, 238, 46, 149, 202, 203, 132},
		},
		{
			dataSize:     1,
			startWith:    []byte{'a'},
			expectedRoot: []byte{52, 75, 204, 142, 172, 129, 37, 14, 145, 137, 103, 203, 11, 162, 209, 205, 30, 169, 213, 72, 20, 28, 243, 24, 242, 2, 92, 43, 169, 59, 110, 210},
		},
		{
			dataSize:     1,
			startWith:    []byte{'1'},
			expectedRoot: []byte{74, 35, 103, 179, 176, 149, 254, 112, 42, 65, 104, 66, 119, 56, 133, 124, 228, 15, 65, 161, 150, 0, 117, 174, 242, 34, 115, 115, 218, 37, 3, 105},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			var (
				data bytes.Buffer
				tree bytes.Buffer
			)

			startSize := len(tc.startWith)
			_, err := data.Write(tc.startWith)
			if err != nil {
				t.Fatalf("Failed to write to data: %v", err)
			}
			_, err = data.Write(make([]byte, tc.dataSize-startSize))
			if err != nil {
				t.Fatalf("Failed to write to data: %v", err)
			}

			root, err := Generate(&data, int64(tc.dataSize), &tree, &tree)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if !bytes.Equal(root, tc.expectedRoot) {
				t.Errorf("Unexpected root")
			}
		})
	}
}
