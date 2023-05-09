// Copyright 2021 The gVisor Authors.
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

package sandbox

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestTotalSystemMemory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    uint64
		err     string
	}{
		{
			name:    "simple",
			content: "MemTotal: 123\n",
			want:    123,
		},
		{
			name:    "kb",
			content: "MemTotal: 123 kB\n",
			want:    123 * 1024,
		},
		{
			name:    "multi-line",
			content: "Something: 123\nMemTotal: 456\nAnotherThing: 789\n",
			want:    456,
		},
		{
			name:    "not-found",
			content: "Something: 123 kB\nAnotherThing: 789 kB\n",
			err:     "not found",
		},
		{
			name:    "no-number",
			content: "MemTotal: \n",
			err:     "malformed",
		},
		{
			name:    "only-unit",
			content: "MemTotal: kB\n",
			err:     "invalid syntax",
		},
		{
			name:    "negative",
			content: "MemTotal: -1\n",
			err:     "invalid syntax",
		},
		{
			name:    "overflow",
			content: fmt.Sprintf("MemTotal: %d kB\n", uint64(math.MaxUint64)),
			err:     "too large",
		},
		{
			name:    "unkown-unit",
			content: "MemTotal: 123 mB\n",
			err:     "unknown unit",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem, err := parseTotalSystemMemory(bytes.NewReader([]byte(tc.content)))
			if len(tc.err) > 0 {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Errorf("parseTotalSystemMemory(%q) invalid error: %v, want: %v", tc.content, err, tc.err)
				}
			} else {
				if tc.want != mem {
					t.Errorf("parseTotalSystemMemory(%q) got: %v, want: %v", tc.content, mem, tc.want)
				}
			}
		})
	}
}
