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

package buffer

import (
	"bytes"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/safemem"
)

func TestSafemem(t *testing.T) {
	const bufferSize = defaultBufferSize

	testCases := []struct {
		name    string
		input   string
		output  string
		readLen int
		op      func(*View)
	}{
		// Basic coverage.
		{
			name:   "short",
			input:  "010",
			output: "010",
		},
		{
			name:   "long",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: "0" + strings.Repeat("1", bufferSize) + "0",
		},
		{
			name:    "short-read",
			input:   "0",
			readLen: 100, // > size.
			output:  "0",
		},
		{
			name:   "zero-read",
			input:  "0",
			output: "",
		},
		{
			name:    "read-empty",
			input:   "",
			readLen: 1, // > size.
			output:  "",
		},

		// Ensure offsets work.
		{
			name:   "offsets-short",
			input:  "012",
			output: "2",
			op: func(v *View) {
				v.TrimFront(2)
			},
		},
		{
			name:   "offsets-long0",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: strings.Repeat("1", bufferSize) + "0",
			op: func(v *View) {
				v.TrimFront(1)
			},
		},
		{
			name:   "offsets-long1",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: strings.Repeat("1", bufferSize-1) + "0",
			op: func(v *View) {
				v.TrimFront(2)
			},
		},
		{
			name:   "offsets-long2",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: "10",
			op: func(v *View) {
				v.TrimFront(bufferSize)
			},
		},

		// Ensure truncation works.
		{
			name:   "truncate-short",
			input:  "012",
			output: "01",
			op: func(v *View) {
				v.Truncate(2)
			},
		},
		{
			name:   "truncate-long0",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: "0" + strings.Repeat("1", bufferSize),
			op: func(v *View) {
				v.Truncate(bufferSize + 1)
			},
		},
		{
			name:   "truncate-long1",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: "0" + strings.Repeat("1", bufferSize-1),
			op: func(v *View) {
				v.Truncate(bufferSize)
			},
		},
		{
			name:   "truncate-long2",
			input:  "0" + strings.Repeat("1", bufferSize) + "0",
			output: "01",
			op: func(v *View) {
				v.Truncate(2)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct the new view.
			var view View
			bs := safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte(tc.input)))
			n, err := view.WriteFromBlocks(bs)
			if err != nil {
				t.Errorf("expected err nil, got %v", err)
			}
			if n != uint64(len(tc.input)) {
				t.Errorf("expected %d bytes, got %d", len(tc.input), n)
			}

			// Run the operation.
			if tc.op != nil {
				tc.op(&view)
			}

			// Read and validate.
			readLen := tc.readLen
			if readLen == 0 {
				readLen = len(tc.output) // Default.
			}
			out := make([]byte, readLen)
			bs = safemem.BlockSeqOf(safemem.BlockFromSafeSlice(out))
			n, err = view.ReadToBlocks(bs)
			if err != nil {
				t.Errorf("expected nil, got %v", err)
			}
			if n != uint64(len(tc.output)) {
				t.Errorf("expected %d bytes, got %d", len(tc.output), n)
			}

			// Ensure the contents are correct.
			if !bytes.Equal(out[:n], []byte(tc.output[:n])) {
				t.Errorf("contents are wrong: expected %q, got %q", tc.output, string(out))
			}
		})
	}
}
