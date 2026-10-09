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
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/types/known/anypb"
)

// goldenPodSandboxConfig is a PodSandboxConfig marshalled by k8s.io/cri-api
// v0.32.3 with typeurl.MarshalAny, as containerd's CRI plugin does:
//
//	Metadata:     {Name: "name", Uid: "uid", Namespace: "ns", Attempt: 3},
//	Hostname:     "host",
//	LogDirectory: "/logs",
//	DnsConfig:    {Servers: ["8.8.8.8"]},
//	PortMappings: [{ContainerPort: 80}],
//	Labels:       {"l": "v"},
//	Annotations:  {"dev.gvisor.flag.debug": "true"},
//	Linux: {
//		CgroupParent: "/kubepods/pod123",
//		SecurityContext: {
//			NamespaceOptions: {Network: NODE, Pid: CONTAINER},
//			Privileged:       true,
//		},
//		Sysctls:   {"net.ipv4.ip_forward": "1"},
//		Overhead:  {CpuShares: 7},
//		Resources: {CpuPeriod: 100000, CpuQuota: -1, CpuShares: 512, MemoryLimitInBytes: 1 << 30},
//	},
const goldenPodSandboxConfig = "0a110a046e616d6512037569641a026e7320031204686f73741a052f6c6f677322090a07382e382e382e382a02105032060a016c1201763a1d0a156465762e677669736f722e666c61672e646562756712047472756542540a102f6b756265706f64732f706f6431323312080a040802100130011a180a136e65742e697076342e69705f666f7277617264120131220218072a1808a08d0610ffffffffffffffffff01188004208080808004"

func TestUnmarshalPodSandboxConfig(t *testing.T) {
	value, err := hex.DecodeString(goldenPodSandboxConfig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalPodSandboxConfig(&anypb.Any{TypeUrl: "runtime.v1.PodSandboxConfig", Value: value})
	if err != nil {
		t.Fatalf("unmarshalPodSandboxConfig: %v", err)
	}
	want := &podSandboxConfig{
		name:         "name",
		uid:          "uid",
		namespace:    "ns",
		hostname:     "host",
		logDirectory: "/logs",
		annotations:  map[string]string{"dev.gvisor.flag.debug": "true"},
		cgroupParent: "/kubepods/pod123",
		sysctls:      map[string]string{"net.ipv4.ip_forward": "1"},
		hostNetwork:  true,
		resources: &podResources{
			cpuPeriod:   100000,
			cpuQuota:    -1,
			cpuShares:   512,
			memoryLimit: 1 << 30,
		},
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(podSandboxConfig{}, podResources{})); diff != "" {
		t.Errorf("unmarshalPodSandboxConfig mismatch (-want +got):\n%s", diff)
	}
}

func TestUnmarshalPodSandboxConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    *anypb.Any
	}{
		{
			name: "wrong type",
			a:    &anypb.Any{TypeUrl: "runtime.v1.ContainerConfig"},
		},
		{
			name: "truncated",
			a:    &anypb.Any{TypeUrl: "runtime.v1.PodSandboxConfig", Value: []byte{0x0a, 0x11, 0x0a}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := unmarshalPodSandboxConfig(tc.a); err == nil {
				t.Errorf("unmarshalPodSandboxConfig = %+v, want error", got)
			}
		})
	}
}
