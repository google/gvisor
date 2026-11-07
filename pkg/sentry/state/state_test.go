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

package state

import (
	"strconv"
	"testing"
)

func TestSavedMemoryFileBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		want     uint64
	}{
		{name: "nilMetadata", metadata: nil, want: 0},
		{name: "missingKey", metadata: map[string]string{}, want: 0},
		{name: "malformedMetadata", metadata: map[string]string{metadataMemoryFileUsedBytesKey: "bad"}, want: 0},
		{
			name:     "validBytes",
			metadata: map[string]string{metadataMemoryFileUsedBytesKey: strconv.FormatUint(200<<20, 10)},
			want:     200 << 20,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SavedMemoryFileBytes(tc.metadata); got != tc.want {
				t.Fatalf("SavedMemoryFileBytes(%v) = %d, want %d", tc.metadata, got, tc.want)
			}
		})
	}
}
