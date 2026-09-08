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

package checkpoint

import (
	"testing"
)

func TestResourceIDClean(t *testing.T) {
	testCases := []struct {
		name string
		in   ResourceID
		want ResourceID
	}{
		{
			name: "empty path",
			in:   ResourceID{ContainerName: "c1", Path: ""},
			want: ResourceID{ContainerName: "c1", Path: ""},
		},
		{
			name: "already clean absolute",
			in:   ResourceID{ContainerName: "c1", Path: "/a/b/c"},
			want: ResourceID{ContainerName: "c1", Path: "/a/b/c"},
		},
		{
			name: "trailing slashes",
			in:   ResourceID{ContainerName: "c1", Path: "/a/b/c///"},
			want: ResourceID{ContainerName: "c1", Path: "/a/b/c"},
		},
		{
			name: "dot-dot and redundant slashes",
			in:   ResourceID{ContainerName: "c1", Path: "/a/b/../c//d/."},
			want: ResourceID{ContainerName: "c1", Path: "/a/c/d"},
		},
		{
			name: "root path",
			in:   ResourceID{ContainerName: "c1", Path: "////"},
			want: ResourceID{ContainerName: "c1", Path: "/"},
		},
		{
			name: "relative path",
			in:   ResourceID{ContainerName: "c1", Path: "a/b/../c"},
			want: ResourceID{ContainerName: "c1", Path: "a/c"},
		},
		{
			name: "empty container name",
			in:   ResourceID{ContainerName: "", Path: "/tmp//"},
			want: ResourceID{ContainerName: "", Path: "/tmp"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Clean()
			if got != tc.want {
				t.Errorf("%+v.Clean() = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}
