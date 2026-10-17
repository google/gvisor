// Copyright 2026 The gVisor Authors.
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

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestCgroupsPath(t *testing.T) {
	for _, tc := range []struct {
		parent string
		want   string
	}{
		{
			parent: "/kubepods/besteffort/pod123",
			want:   "/kubepods/besteffort/pod123/sb",
		},
		{
			parent: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice",
			want:   "kubepods-besteffort-pod123.slice:cri-containerd:sb",
		},
	} {
		if got := cgroupsPath(tc.parent, "sb"); got != tc.want {
			t.Errorf("cgroupsPath(%q) = %q, want %q", tc.parent, got, tc.want)
		}
	}
}

func TestSandboxSpec(t *testing.T) {
	config := &podSandboxConfig{
		name:         "name",
		namespace:    "ns",
		uid:          "uid",
		hostname:     "host",
		logDirectory: "/logs",
		annotations: map[string]string{
			"dev.gvisor.flag.debug": "true",
			"other":                 "x",
		},
		cgroupParent: "/kubepods/pod123",
		sysctls:      map[string]string{"net.ipv4.ip_forward": "1"},
		resources: &podResources{
			cpuPeriod:   100000,
			cpuQuota:    50000,
			cpuShares:   512,
			memoryLimit: 1 << 30,
		},
	}
	passed := map[string]string{"dev.gvisor.flag.strace": "true"}

	got := sandboxSpec("sb", "/var/run/netns/cni-1", passed, config)

	want := &specs.Spec{
		Version:  specs.Version,
		Hostname: "host",
		Annotations: map[string]string{
			"dev.gvisor.flag.strace":                  "true",
			"io.kubernetes.cri.container-type":        "sandbox",
			"io.kubernetes.cri.sandbox-id":            "sb",
			"io.kubernetes.cri.sandbox-name":          "name",
			"io.kubernetes.cri.sandbox-namespace":     "ns",
			"io.kubernetes.cri.sandbox-uid":           "uid",
			"io.kubernetes.cri.sandbox-log-directory": "/logs",
			"io.kubernetes.cri.sandbox-cpu-period":    "100000",
			"io.kubernetes.cri.sandbox-cpu-quota":     "50000",
			"io.kubernetes.cri.sandbox-cpu-shares":    "512",
			"io.kubernetes.cri.sandbox-mem":           "1073741824",
		},
		Linux: &specs.Linux{
			CgroupsPath: "/kubepods/pod123/sb",
			Sysctl:      map[string]string{"net.ipv4.ip_forward": "1"},
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.NetworkNamespace, Path: "/var/run/netns/cni-1"},
			},
		},
	}
	// Pod annotations are not copied; Process and Root stay nil.
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("sandboxSpec mismatch (-want +got):\n%s", diff)
	}
}

func TestSandboxSpecHostNetwork(t *testing.T) {
	got := sandboxSpec("sb", "", nil, &podSandboxConfig{hostNetwork: true})
	if len(got.Linux.Namespaces) != 0 {
		t.Errorf("sandboxSpec namespaces = %+v, want none", got.Linux.Namespaces)
	}
	if got.Linux.CgroupsPath != "" {
		t.Errorf("sandboxSpec cgroups path = %q, want none", got.Linux.CgroupsPath)
	}
}
