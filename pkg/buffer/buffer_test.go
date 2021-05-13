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

package buffer

import (
	"bytes"
	"testing"
)

func TestBufferRemove(t *testing.T) {
	sample := []byte("01234567")

	// Success cases
	for _, tc := range []struct {
		desc string
		data []byte
		rng  Range
		want []byte
	}{
		{
			desc: "empty slice",
		},
		{
			desc: "empty range",
			data: sample,
			want: sample,
		},
		{
			desc: "empty range with positive begin",
			data: sample,
			rng:  Range{begin: 1, end: 1},
			want: sample,
		},
		{
			desc: "range at beginning",
			data: sample,
			rng:  Range{begin: 0, end: 1},
			want: sample[1:],
		},
		{
			desc: "range in middle",
			data: sample,
			rng:  Range{begin: 2, end: 4},
			want: []byte("014567"),
		},
		{
			desc: "range at end",
			data: sample,
			rng:  Range{begin: 7, end: 8},
			want: sample[:7],
		},
		{
			desc: "range all",
			data: sample,
			rng:  Range{begin: 0, end: 8},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var buf buffer
			buf.initWithData(tc.data)
			if ok := buf.Remove(tc.rng); !ok {
				t.Errorf("buf.Remove(%#v) = false, want true", tc.rng)
			} else if got := buf.ReadSlice(); !bytes.Equal(got, tc.want) {
				t.Errorf("buf.ReadSlice() = %q, want %q", got, tc.want)
			}
		})
	}

	// Failure cases
	for _, tc := range []struct {
		desc string
		data []byte
		rng  Range
	}{
		{
			desc: "begin out-of-range",
			data: sample,
			rng:  Range{begin: -1, end: 4},
		},
		{
			desc: "end out-of-range",
			data: sample,
			rng:  Range{begin: 4, end: 9},
		},
		{
			desc: "both out-of-range",
			data: sample,
			rng:  Range{begin: -100, end: 100},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var buf buffer
			buf.initWithData(tc.data)
			if ok := buf.Remove(tc.rng); ok {
				t.Errorf("buf.Remove(%#v) = true, want false", tc.rng)
			}
		})
	}
}
