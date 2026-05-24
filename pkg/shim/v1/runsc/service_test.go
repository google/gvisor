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
	"errors"
	"path/filepath"
	"testing"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

func TestContainerUpdateNilResources(t *testing.T) {
	c := &Container{}
	err := c.Update(t.Context(), &task.UpdateTaskRequest{ID: "x", Resources: nil})
	if !errors.Is(err, errdefs.ErrInvalidArgument) {
		t.Fatalf("Update(nil Resources): %v, want ErrInvalidArgument", err)
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

func TestNewInitSandboxDefault(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantSandbox bool
	}{
		{
			name:        "non-cri",
			wantSandbox: true,
		},
		{
			name: "cri-sandbox",
			annotations: map[string]string{
				utils.ContainerTypeAnnotation: "sandbox",
			},
			wantSandbox: true,
		},
		{
			name: "cri-container",
			annotations: map[string]string{
				utils.ContainerTypeAnnotation: utils.ContainerTypeContainer,
			},
			wantSandbox: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := t.TempDir()
			spec := specs.Spec{
				Version:     specs.Version,
				Annotations: tc.annotations,
			}
			if err := utils.WriteSpec(bundle, &spec); err != nil {
				t.Fatalf("WriteSpec: %v", err)
			}
			p, err := newInit(filepath.Join(bundle, "work"), "default", nil, &proc.CreateConfig{
				ID:     "test",
				Bundle: bundle,
			}, &Options{}, "")
			if err != nil {
				t.Fatalf("newInit: %v", err)
			}
			if got := p.Sandbox; got != tc.wantSandbox {
				t.Fatalf("p.Sandbox: got %v, want %v", got, tc.wantSandbox)
			}
		})
	}
}
