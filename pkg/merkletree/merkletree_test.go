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
