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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
	"gvisor.dev/gvisor/runsc/specutils"
)

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

func TestSandboxDetection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantSandbox bool
	}{
		{
			name:        "no-annotation (non-CRI caller like BuildKit or ctr)",
			annotations: nil,
			wantSandbox: true,
		},
		{
			name:        "empty-annotations",
			annotations: map[string]string{},
			wantSandbox: true,
		},
		{
			name: "containerd-sandbox",
			annotations: map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeSandbox,
			},
			wantSandbox: true,
		},
		{
			name: "containerd-container",
			annotations: map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
			},
			wantSandbox: false,
		},
		{
			name: "crio-sandbox",
			annotations: map[string]string{
				specutils.CRIOContainerTypeAnnotation: specutils.CRIOContainerTypeSandbox,
			},
			wantSandbox: true,
		},
		{
			name: "crio-container",
			annotations: map[string]string{
				specutils.CRIOContainerTypeAnnotation: specutils.CRIOContainerTypeContainer,
			},
			wantSandbox: false,
		},
		{
			name: "unknown-annotation-value",
			annotations: map[string]string{
				specutils.ContainerdContainerTypeAnnotation: "unknown-value",
			},
			wantSandbox: false,
		},
		{
			name: "both-annotations-container-wins",
			annotations: map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
				specutils.CRIOContainerTypeAnnotation:      specutils.CRIOContainerTypeSandbox,
			},
			// containerd annotation is checked first
			wantSandbox: false,
		},
		{
			name: "unrelated-annotations-treated-as-unspecified",
			annotations: map[string]string{
				"some.other.annotation": "value",
			},
			wantSandbox: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &specs.Spec{Annotations: tc.annotations}
			ct := specutils.SpecContainerType(spec)
			got := ct == specutils.ContainerTypeSandbox || ct == specutils.ContainerTypeUnspecified
			if got != tc.wantSandbox {
				t.Errorf("sandbox detection for %v: got %v, want %v (containerType=%v)", tc.annotations, got, tc.wantSandbox, ct)
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
