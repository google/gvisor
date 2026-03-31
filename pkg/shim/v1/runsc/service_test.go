// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"strings"
	"testing"

	"github.com/containerd/containerd/runtime/v2/task"
	runc "github.com/containerd/go-runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

// TestTaskStatsProtobufTypeURLs checks that v1 and v2 stats marshal to distinct type
// URLs, matching what containerd expects for cgroup v1 vs unified v2 hosts.
func TestTaskStatsProtobufTypeURLs(t *testing.T) {
	s := &runscService{}
	var st runc.Stats
	req := &task.StatsRequest{ID: "test"}
	v1resp, err := s.getV1Stats(&st, req)
	if err != nil {
		t.Fatalf("getV1Stats: %v", err)
	}
	v2resp, err := s.getV2Stats(&st, req)
	if err != nil {
		t.Fatalf("getV2Stats: %v", err)
	}
	if v1resp.Stats.TypeUrl == v2resp.Stats.TypeUrl {
		t.Fatalf("v1 and v2 TypeUrl must differ, both %q", v1resp.Stats.TypeUrl)
	}
	if !strings.Contains(v1resp.Stats.TypeUrl, "cgroups.v1") {
		t.Errorf("v1 TypeUrl = %q, want substring cgroups.v1", v1resp.Stats.TypeUrl)
	}
	if !strings.Contains(v2resp.Stats.TypeUrl, "cgroups.v2") {
		t.Errorf("v2 TypeUrl = %q, want substring cgroups.v2", v2resp.Stats.TypeUrl)
	}
}

func TestCgroupPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple",
			path: "foo/pod123/container",
			want: "foo/pod123",
		},
		{
			name: "absolute",
			path: "/foo/pod123/container",
			want: "/foo/pod123",
		},
		{
			name: "no-container",
			path: "foo/pod123",
			want: "",
		},
		{
			name: "no-container-absolute",
			path: "/foo/pod123",
			want: "",
		},
		{
			name: "double-pod",
			path: "/foo/podium/pod123/container",
			want: "/foo/podium/pod123",
		},
		{
			name: "start-pod",
			path: "pod123/container",
			want: "pod123",
		},
		{
			name: "start-pod-absolute",
			path: "/pod123/container",
			want: "/pod123",
		},
		{
			name: "slashes",
			path: "///foo/////pod123//////container",
			want: "/foo/pod123",
		},
		{
			name: "no-pod",
			path: "/foo/nopod123/container",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: tc.path,
				},
			}
			updated := setPodCgroup(&spec)
			if got := spec.Annotations[cgroupParentAnnotation]; got != tc.want {
				t.Errorf("setPodCgroup(%q), want: %q, got: %q", tc.path, tc.want, got)
			}
			if shouldUpdate := len(tc.want) > 0; shouldUpdate != updated {
				t.Errorf("setPodCgroup(%q)=%v, want: %v", tc.path, updated, shouldUpdate)
			}
		})
	}
}

// Test cases that cgroup path should not be updated.
func TestCgroupNoUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
	}{
		{
			name: "empty",
			spec: &specs.Spec{},
		},
		{
			name: "subcontainer",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: "foo/pod123/container",
				},
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation: utils.ContainerTypeContainer,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if updated := setPodCgroup(tc.spec); updated {
				t.Errorf("setPodCgroup(%+v), got: %v, want: false", tc.spec.Linux, updated)
			}
		})
	}
}
