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
		defPfx  string
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
			name: "directory prefixed fs",
			in:   []string{"fs/=/"},
			want: []Bundle{{
				Prefix: "fs/",
				Paths:  []checkpoint.ResourceID{{Path: "/"}},
			}},
		},
		{
			name: "multiple paths with same prefix",
			in:   []string{"fs=/data", "fs=c1:/tmp"},
			want: []Bundle{{
				Prefix: "fs",
				Paths: []checkpoint.ResourceID{
					{Path: "/data"},
					{ContainerName: "c1", Path: "/tmp"},
				},
			}},
		},
		{
			name: "grouped bundles preserving prefix order",
			in:   []string{"rootfs=/", "dur1=c1:/data", "dur1=/logs", "extra=/extra"},
			want: []Bundle{
				{Prefix: "rootfs", Paths: []checkpoint.ResourceID{{Path: "/"}}},
				{Prefix: "dur1", Paths: []checkpoint.ResourceID{{ContainerName: "c1", Path: "/data"}, {Path: "/logs"}}},
				{Prefix: "extra", Paths: []checkpoint.ResourceID{{Path: "/extra"}}},
			},
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
			name:    "duplicate paths across bundles",
			in:      []string{"rootfs=/", "fs=/"},
			wantErr: true,
		},
		{
			name:    "empty prefix",
			in:      []string{"=/data"},
			wantErr: true,
		},
		{
			name:    "invalid leading slash prefix",
			in:      []string{"/sub=/data"},
			wantErr: true,
		},
		{
			name: "cleaned double slash prefix",
			in:   []string{"sub//dir=/data"},
			want: []Bundle{{
				Prefix: "sub/dir",
				Paths:  []checkpoint.ResourceID{{Path: "/data"}},
			}},
		},
		{
			name: "cleaned dot and dot dot prefix",
			in:   []string{"./sub/../dir/=/data", "x/../dir/=/logs"},
			want: []Bundle{{
				Prefix: "dir/",
				Paths:  []checkpoint.ResourceID{{Path: "/data"}, {Path: "/logs"}},
			}},
		},
		{
			name:    "conflicting cleaned prefix",
			in:      []string{"x/../fs=/", "fs/=/data"},
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
			name:    "invalid escaping dot dot prefix",
			in:      []string{"sub/../../dir=/data"},
			wantErr: true,
		},
		{
			name:    "invalid dot file prefix",
			in:      []string{".=/data"},
			wantErr: true,
		},
		{
			name:    "invalid nested dot dot to root prefix",
			in:      []string{"sub/..=/data"},
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
		{
			name:    "conflicting file and directory prefix",
			in:      []string{"foo=/", "foo/=/data"},
			wantErr: true,
		},
		{
			name:    "conflicting nested prefixes",
			in:      []string{"a/b=/", "a/b/c=/data"},
			wantErr: true,
		},
		{
			name: "non-conflicting sibling nested prefixes",
			in:   []string{"bundles/rootfs/=/", "bundles/fs=/data"},
			want: []Bundle{
				{Prefix: "bundles/rootfs/", Paths: []checkpoint.ResourceID{{Path: "/"}}},
				{Prefix: "bundles/fs", Paths: []checkpoint.ResourceID{{Path: "/data"}}},
			},
		},
		{
			name:   "merges unprefixed and explicit default prefix",
			in:     []string{"rootfs=/", "fs=/data", "/extra"},
			defPfx: "fs",
			want: []Bundle{
				{Prefix: "rootfs", Paths: []checkpoint.ResourceID{{Path: "/"}}},
				{Prefix: "fs", Paths: []checkpoint.ResourceID{{Path: "/data"}, {Path: "/extra"}}},
			},
		},
		{
			name:    "rejects unprefixed conflicting with directory default prefix",
			in:      []string{"/", "fs/=/data"},
			defPfx:  "fs",
			wantErr: true,
		},
		{
			name:    "unprefixed bundle conflicts with prefixed bundle",
			in:      []string{"/", "fs=/data"},
			wantErr: true,
		},
		{
			name:    "prefixed bundle conflicts with later unprefixed bundle",
			in:      []string{"sub/fs=/data", "/"},
			wantErr: true,
		},
		{
			name:    "unprefixed bundle conflicts with directory prefix",
			in:      []string{"/", "sub/=/data"},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundles, err := ParseBundlesWithDefaultPrefix(tc.in, tc.defPfx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseBundlesWithDefaultPrefix(%q, %q) error = %v, wantErr %v", tc.in, tc.defPfx, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(tc.want, bundles); diff != "" {
					t.Errorf("ParseBundlesWithDefaultPrefix(%q, %q) diff (-want +got):\n%s", tc.in, tc.defPfx, diff)
				}
			}
		})
	}
}
