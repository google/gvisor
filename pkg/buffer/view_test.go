// Copyright 2018 The gVisor Authors.
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
)

func TestView(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		output string
		ops    []func(*View)
	}{
		// Prepend.
		{
			name:  "prepend",
			input: "world",
			ops: []func(*View){
				func(v *View) {
					v.Prepend([]byte("hello "))
				},
			},
			output: "hello world",
		},
		{
			name:  "prepend fill",
			input: strings.Repeat("1", bufferSize-1),
			ops: []func(*View){
				func(v *View) {
					v.Prepend([]byte("0"))
				},
			},
			output: "0" + strings.Repeat("1", bufferSize-1),
		},
		{
			name:  "prepend overflow",
			input: strings.Repeat("1", bufferSize),
			ops: []func(*View){
				func(v *View) {
					v.Prepend([]byte("0"))
				},
			},
			output: "0" + strings.Repeat("1", bufferSize),
		},
		{
			name:  "prepend multiple buffers",
			input: strings.Repeat("1", bufferSize-1),
			ops: []func(*View){
				func(v *View) {
					v.Prepend([]byte(strings.Repeat("0", bufferSize*3)))
				},
			},
			output: strings.Repeat("0", bufferSize*3) + strings.Repeat("1", bufferSize-1),
		},

		// Append.
		{
			name:  "append",
			input: "hello",
			ops: []func(*View){
				func(v *View) {
					v.Append([]byte(" world"))
				},
			},
			output: "hello world",
		},
		{
			name:  "append fill",
			input: strings.Repeat("1", bufferSize-1),
			ops: []func(*View){
				func(v *View) {
					v.Append([]byte("0"))
				},
			},
			output: strings.Repeat("1", bufferSize-1) + "0",
		},
		{
			name:  "append overflow",
			input: strings.Repeat("1", bufferSize),
			ops: []func(*View){
				func(v *View) {
					v.Append([]byte("0"))
				},
			},
			output: strings.Repeat("1", bufferSize) + "0",
		},
		{
			name:  "append multiple buffers",
			input: strings.Repeat("1", bufferSize-1),
			ops: []func(*View){
				func(v *View) {
					v.Append([]byte(strings.Repeat("0", bufferSize*3)))
				},
			},
			output: strings.Repeat("1", bufferSize-1) + strings.Repeat("0", bufferSize*3),
		},

		// Truncate.
		{
			name:  "truncate",
			input: "hello world",
			ops: []func(*View){
				func(v *View) {
					v.Truncate(5)
				},
			},
			output: "hello",
		},
		{
			name:  "truncate multiple buffers",
			input: strings.Repeat("1", bufferSize*2),
			ops: []func(*View){
				func(v *View) {
					v.Truncate(bufferSize*2 - 1)
				},
			},
			output: strings.Repeat("1", bufferSize*2-1),
		},
		{
			name:  "truncate multiple buffers to one buffer",
			input: strings.Repeat("1", bufferSize*2),
			ops: []func(*View){
				func(v *View) {
					v.Truncate(5)
				},
			},
			output: "11111",
		},

		// TrimFront.
		{
			name:  "trim",
			input: "hello world",
			ops: []func(*View){
				func(v *View) {
					v.TrimFront(6)
				},
			},
			output: "world",
		},
		{
			name:  "trim multiple buffers",
			input: strings.Repeat("1", bufferSize*2),
			ops: []func(*View){
				func(v *View) {
					v.TrimFront(1)
				},
			},
			output: strings.Repeat("1", bufferSize*2-1),
		},
		{
			name:  "trim multiple buffers to one buffer",
			input: strings.Repeat("1", bufferSize*2),
			ops: []func(*View){
				func(v *View) {
					v.TrimFront(bufferSize*2 - 1)
				},
			},
			output: "1",
		},

		// Grow.
		{
			name:  "grow",
			input: "hello world",
			ops: []func(*View){
				func(v *View) {
					v.Grow(1, true)
				},
			},
			output: "hello world",
		},
		{
			name: "grow from zero",
			ops: []func(*View){
				func(v *View) {
					v.Grow(1024, true)
				},
			},
			output: strings.Repeat("\x00", 1024),
		},
		{
			name:  "grow from non-zero",
			input: strings.Repeat("1", bufferSize),
			ops: []func(*View){
				func(v *View) {
					v.Grow(bufferSize*2, true)
				},
			},
			output: strings.Repeat("1", bufferSize) + strings.Repeat("\x00", bufferSize),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct the new view.
			var view View
			view.Append([]byte(tc.input))

			// Run all operations.
			for _, op := range tc.ops {
				op(&view)
			}

			// Flatten and validate.
			out := view.Flatten()
			if !bytes.Equal([]byte(tc.output), out) {
				t.Errorf("expected %q, got %q", tc.output, string(out))
			}

			// Ensure the size is correct.
			if len(out) != int(view.Size()) {
				t.Errorf("size is wrong: expected %d, got %d", len(out), view.Size())
			}
		})
	}
}
