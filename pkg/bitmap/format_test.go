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

package bitmap

import (
	"fmt"
	"slices"
	"testing"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		input  []uint32
		output string
	}{
		{[]uint32{1, 2, 3, 4, 7}, "1-4,7"},
		{[]uint32{2}, "2"},
		{[]uint32{0, 1, 2}, "0-2"},
		{[]uint32{}, ""},
		{[]uint32{1, 3, 4, 5, 6, 9, 11, 13, 14, 15, 16, 17}, "1,3-6,9,11,13-17"},
		{[]uint32{2, 3, 10, 12, 13, 14, 15, 16, 20, 21, 33, 34, 47}, "2-3,10,12-16,20-21,33-34,47"},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			b := New(64)
			for _, v := range tt.input {
				b.Add(v)
			}
			s := FormatList(&b)
			if s != tt.output {
				t.Errorf("Expected %q, got %q", tt.output, s)
			}
			b1, err := ParseList(s, 64)
			if err != nil {
				t.Fatalf("Failed to parse formatted bitmap: %v", err)
			}
			if got, want := b1.ToSlice(), b.ToSlice(); !slices.Equal(got, want) {
				t.Errorf("Parsing formatted output doesn't result in the original bitmap. Got %v, want %v", got, want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		input      string
		output     []uint32
		shouldFail bool
	}{
		{"1", []uint32{1}, false},
		{"", []uint32{}, false},
		{"1,2,3,4", []uint32{1, 2, 3, 4}, false},
		{"1-4", []uint32{1, 2, 3, 4}, false},
		{"1,2-4", []uint32{1, 2, 3, 4}, false},
		{"1,2-3,4", []uint32{1, 2, 3, 4}, false},
		{"1-2,3,4,10,11", []uint32{1, 2, 3, 4, 10, 11}, false},
		{"1,2-4,5,16", []uint32{1, 2, 3, 4, 5, 16}, false},
		{"abc", []uint32{}, true},
		{"1,3-2,4", []uint32{}, true},
		{"1,3-3,4", []uint32{1, 3, 4}, false},
		{"1,2,3\000,4", []uint32{1, 2, 3}, false},
		{"1,2,3\n,4", []uint32{1, 2, 3}, false},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			b, err := ParseList(tt.input, 64)
			if tt.shouldFail {
				if err == nil {
					t.Fatalf("Expected parsing of %q to fail, but it didn't", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("Failed to parse bitmap: %v", err)
				return
			}

			got := b.ToSlice()
			if !slices.Equal(got, tt.output) {
				t.Errorf("Parsed bitmap doesn't match what we expected. Got %v, want %v", got, tt.output)
			}

		})
	}
}

// Keep invalid indices small so a bounds regression fails without causing a
// large allocation or overflowing the parser's range counter.
func TestParseBounds(t *testing.T) {
	for _, test := range []struct {
		name      string
		input     string
		limit     uint32
		want      []uint32
		wantError bool
	}{
		{name: "empty", input: "", limit: 0, want: []uint32{}},
		{name: "zero_limit", input: "0", limit: 0, wantError: true},
		{name: "last_bit", input: "63", limit: 64, want: []uint32{63}},
		{name: "at_limit", input: "64", limit: 64, wantError: true},
		{name: "range_at_limit", input: "0-64", limit: 64, wantError: true},
		{name: "next_word", input: "64", limit: 65, want: []uint32{64}},
		{name: "unaligned_limit", input: "64-65", limit: 65, wantError: true},
		{name: "later_token", input: "1,65", limit: 65, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseList(test.input, test.limit)
			if (err != nil) != test.wantError {
				t.Fatalf("ParseList(%q, %d) error = %v, want error: %t", test.input, test.limit, err, test.wantError)
			}
			if test.wantError {
				if got != nil {
					t.Fatalf("ParseList(%q, %d) returned a partial bitmap on error", test.input, test.limit)
				}
				return
			}
			if !slices.Equal(got.ToSlice(), test.want) {
				t.Errorf("ParseList(%q, %d) = %v, want %v", test.input, test.limit, got.ToSlice(), test.want)
			}
		})
	}
}
