// Copyright 2018 Google Inc.
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

package linewriter

import (
	"bytes"
	"testing"
)

func TestWriter(t *testing.T) {
	testCases := []struct {
		input []string
		want  []string
	}{
		{
			input: []string{"1\n", "2\n"},
			want:  []string{"1", "2"},
		},
		{
			input: []string{"1\n", "\n", "2\n"},
			want:  []string{"1", "", "2"},
		},
		{
			input: []string{"1\n2\n", "3\n"},
			want:  []string{"1", "2", "3"},
		},
		{
			input: []string{"1", "2\n"},
			want:  []string{"12"},
		},
		{
			// Data with no newline yet is omitted.
			input: []string{"1\n", "2\n", "3"},
			want:  []string{"1", "2"},
		},
	}

	for _, c := range testCases {
		var lines [][]byte

		w := NewWriter(func(p []byte) {
			// We must not retain p, so we must make a copy.
			b := make([]byte, len(p))
			copy(b, p)

			lines = append(lines, b)
		})

		for _, in := range c.input {
			n, err := w.Write([]byte(in))
			if err != nil {
				t.Errorf("Write(%q) err got %v want nil (case %+v)", in, err, c)
			}
			if n != len(in) {
				t.Errorf("Write(%q) b got %d want %d (case %+v)", in, n, len(in), c)
			}
		}

		if len(lines) != len(c.want) {
			t.Errorf("len(lines) got %d want %d (case %+v)", len(lines), len(c.want), c)
		}

		for i := range lines {
			if !bytes.Equal(lines[i], []byte(c.want[i])) {
				t.Errorf("item %d got %q want %q (case %+v)", i, lines[i], c.want[i], c)
			}
		}
	}
}
