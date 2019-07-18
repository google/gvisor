// Copyright 2019 The gVisor Authors.
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

package fspath

import (
	"testing"
)

func TestBuilder(t *testing.T) {
	type testCase struct {
		pcs   []string // path components in reverse order
		after string
		want  string
	}
	tests := []testCase{
		{
			// Empty case.
		},
		{
			pcs:  []string{"foo"},
			want: "foo",
		},
		{
			pcs:  []string{"foo", "bar", "baz"},
			want: "baz/bar/foo",
		},
		{
			pcs:   []string{"foo", "bar"},
			after: " (deleted)",
			want:  "bar/foo (deleted)",
		},
	}

	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			var b Builder
			for _, pc := range test.pcs {
				b.PrependComponent(pc)
			}
			b.AppendString(test.after)
			if got := b.String(); got != test.want {
				t.Errorf("got %q, wanted %q", got, test.want)
			}
		})
	}
}
