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

package boot

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
)

func TestParseFSCheckpointPaths(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		want      []checkpoint.ResourceID
		expectErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single clean path",
			input: "/tmp",
			want:  []checkpoint.ResourceID{{Path: "/tmp"}},
		},
		{
			name:  "trailing slash cleaned",
			input: "/tmp/",
			want:  []checkpoint.ResourceID{{Path: "/tmp"}},
		},
		{
			name:  "multiple paths with spaces and redundant slashes",
			input: " /tmp/ , /var//run/. , / ",
			want: []checkpoint.ResourceID{
				{Path: "/tmp"},
				{Path: "/var/run"},
				{Path: "/"},
			},
		},
		{
			name:  "container prefixed paths",
			input: "c1:/tmp/ , c2:/data/app/..",
			want: []checkpoint.ResourceID{
				{ContainerName: "c1", Path: "/tmp"},
				{ContainerName: "c2", Path: "/data"},
			},
		},
		{
			name:  "all-tmpfs keyword",
			input: "all-tmpfs, c1:all-tmpfs",
			want: []checkpoint.ResourceID{
				{Path: "all-tmpfs"},
				{ContainerName: "c1", Path: "all-tmpfs"},
			},
		},
		{
			name:      "empty container path error",
			input:     "c1:",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFSCheckpointPaths(tc.input)
			if (err != nil) != tc.expectErr {
				t.Fatalf("ParseFSCheckpointPaths(%q) err = %v, expectErr = %v", tc.input, err, tc.expectErr)
			}
			if !tc.expectErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseFSCheckpointPaths(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
