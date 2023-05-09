// Copyright 2023 The gVisor Authors.
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

package gohacks

import (
	"reflect"
	"testing"
)

func TestImmutableBytesFromString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{
			name:  "abc",
			input: "abc",
			want:  []byte("abc"),
		},
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			name:  "subslice-empty",
			input: "abc"[:0],
			want:  []byte(""),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ImmutableBytesFromString(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got contents %v (len %d cap %d) want %v (len %d cap %d)", got, len(got), cap(got), tc.want, len(tc.want), cap(tc.want))
			}
		})
	}
}

func TestStringFromImmutableBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "abc",
			input: []byte("abc"),
			want:  "abc",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "nil",
			input: nil,
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := StringFromImmutableBytes(tc.input)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
