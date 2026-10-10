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

package specutils

import (
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestPrepareUserNamespaceForStart(t *testing.T) {
	spec := &specs.Spec{
		Linux: &specs.Linux{
			UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 65536, Size: 65536}},
			GIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 65536, Size: 65536}},
		},
	}
	withPath := specs.LinuxNamespace{Type: specs.UserNamespace, Path: "/proc/123/ns/user"}

	got := PrepareUserNamespaceForStart(withPath, spec)
	if got.Path != "" {
		t.Fatalf("PrepareUserNamespaceForStart() Path = %q, want empty", got.Path)
	}
	if got.Type != specs.UserNamespace {
		t.Fatalf("PrepareUserNamespaceForStart() Type = %v, want user", got.Type)
	}

	unchanged := PrepareUserNamespaceForStart(withPath, &specs.Spec{})
	if unchanged.Path != withPath.Path {
		t.Fatalf("PrepareUserNamespaceForStart() without mappings changed Path")
	}

	noPath := specs.LinuxNamespace{Type: specs.UserNamespace}
	if got := PrepareUserNamespaceForStart(noPath, spec); got.Path != "" || got.Type != specs.UserNamespace {
		t.Fatalf("PrepareUserNamespaceForStart() without Path changed namespace: %+v", got)
	}
}

func TestValidatePodUserNamespaceNetwork(t *testing.T) {
	podUsernsSpec := &specs.Spec{
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.UserNamespace, Path: "/proc/1/ns/user"},
			},
			UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 65536, Size: 65536}},
		},
	}

	if err := ValidatePodUserNamespaceNetwork(true, podUsernsSpec); !errors.Is(err, ErrHostNetworkPodUserNamespace) {
		t.Fatalf("ValidatePodUserNamespaceNetwork(host, pod userns) = %v, want ErrHostNetworkPodUserNamespace", err)
	}
	if err := ValidatePodUserNamespaceNetwork(false, podUsernsSpec); err != nil {
		t.Fatalf("ValidatePodUserNamespaceNetwork(netstack, pod userns) = %v, want nil", err)
	}
	if err := ValidatePodUserNamespaceNetwork(true, &specs.Spec{}); err != nil {
		t.Fatalf("ValidatePodUserNamespaceNetwork(host, no userns) = %v, want nil", err)
	}
}
