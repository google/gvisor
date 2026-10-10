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

package fscheckpoint

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
)

func TestParseBundles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []string
		wantErr bool
		want    []Bundle
	}{
		{
			name: "empty",
			in:   []string{""},
		},
		{
			name: "all-tmpfs",
			in:   []string{"all-tmpfs"},
			want: []Bundle{{
				Paths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
			}},
		},
		{
			name: "clean absolute path",
			in:   []string{"/data"},
			want: []Bundle{{
				Paths: []checkpoint.ResourceID{{Path: "/data"}},
			}},
		},
		{
			name: "container and clean absolute path",
			in:   []string{"c1:/data"},
			want: []Bundle{{
				Paths: []checkpoint.ResourceID{{ContainerName: "c1", Path: "/data"}},
			}},
		},
		{
			name: "multiple clean paths",
			in:   []string{"c1:/data", "c2:/tmp", "c1:/logs"},
			want: []Bundle{{
				Paths: []checkpoint.ResourceID{
					{ContainerName: "c1", Path: "/data"},
					{ContainerName: "c2", Path: "/tmp"},
					{ContainerName: "c1", Path: "/logs"},
				},
			}},
		},
		{
			name: "prefixed rootfs",
			in:   []string{"rootfs=/"},
			want: []Bundle{{
				Prefix: "rootfs",
				Paths:  []checkpoint.ResourceID{{Path: "/"}},
			}},
		},
		{
			name: "directory prefixed fs/",
			in:   []string{"fs/=/"},
			want: []Bundle{{
				Prefix: "fs/",
				Paths:  []checkpoint.ResourceID{{Path: "/"}},
			}},
		},
		{
			name:    "multiple bundles rejected",
			in:      []string{"rootfs=/", "fs=/data"},
			wantErr: true,
		},
		{
			name:    "comma separated rejected",
			in:      []string{"c1:/data, c2:/tmp"},
			wantErr: true,
		},
		{
			name:    "overlap with all-tmpfs",
			in:      []string{"c1:/data", "all-tmpfs"},
			wantErr: true,
		},
		{
			name:    "duplicate paths",
			in:      []string{"/data", "/data"},
			wantErr: true,
		},
		{
			name:    "empty prefix",
			in:      []string{"=/data"},
			wantErr: true,
		},
		{
			name:    "invalid prefix with slash",
			in:      []string{"sub/dir=/data"},
			wantErr: true,
		},
		{
			name:    "invalid nested directory prefix",
			in:      []string{"sub/dir/=/data"},
			wantErr: true,
		},
		{
			name:    "invalid slash only prefix",
			in:      []string{"/=/data"},
			wantErr: true,
		},
		{
			name:    "invalid dot directory prefix",
			in:      []string{"./=/data"},
			wantErr: true,
		},
		{
			name:    "invalid dot dot directory prefix",
			in:      []string{"../=/data"},
			wantErr: true,
		},
		{
			name:    "uncleaned trailing slash",
			in:      []string{"/data/"},
			wantErr: true,
		},
		{
			name:    "uncleaned redundant slash",
			in:      []string{"/data//dir"},
			wantErr: true,
		},
		{
			name:    "uncleaned root slashes",
			in:      []string{"//"},
			wantErr: true,
		},
		{
			name:    "relative path",
			in:      []string{"data"},
			wantErr: true,
		},
		{
			name:    "container with empty path",
			in:      []string{"c1:"},
			wantErr: true,
		},
		{
			name:    "empty container with colon",
			in:      []string{":/data"},
			wantErr: true,
		},
		{
			name:    "uncleaned dot",
			in:      []string{"/data/./sub"},
			wantErr: true,
		},
		{
			name:    "uncleaned dot dot",
			in:      []string{"/data/../sub"},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundles, err := ParseBundles(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseBundles(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(tc.want, bundles); diff != "" {
					t.Errorf("ParseBundles(%q) diff (-want +got):\n%s", tc.in, diff)
				}
			}
		})
	}
}
