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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
)

func TestLinuxSpecHasNvidiaControlDevice(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
		want bool
	}{
		{"nil spec", nil, false},
		{"no linux", &specs.Spec{}, false},
		{"empty devices", &specs.Spec{Linux: &specs.Linux{}}, false},
		{"other device", &specs.Spec{Linux: &specs.Linux{Devices: []specs.LinuxDevice{{Path: "/dev/null"}}}}, false},
		{"nvidiactl", &specs.Spec{Linux: &specs.Linux{Devices: []specs.LinuxDevice{{Path: "/dev/nvidiactl"}}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LinuxSpecHasNvidiaControlDevice(tc.spec); got != tc.want {
				t.Errorf("LinuxSpecHasNvidiaControlDevice() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGPUFunctionalityNeedsNvidiaContainerCLIConfigureMatchesViaHook(t *testing.T) {
	conf := &config.Config{NVProxy: true}
	base := &specs.Spec{
		Process: &specs.Process{Env: []string{"NVIDIA_VISIBLE_DEVICES=all"}},
		Hooks: &specs.Hooks{
			Prestart: []specs.Hook{{Path: "/usr/bin/nvidia-container-runtime-hook"}},
		},
	}
	if a, b := GPUFunctionalityNeedsNvidiaContainerCLIConfigure(base, conf), GPUFunctionalityRequestedViaHook(base, conf); a != b {
		t.Errorf("mismatch: NeedsNvidiaContainerCLIConfigure=%v ViaHook=%v", a, b)
	}
}

func TestGPUFunctionalityNeedsSyntheticNvidiaDevices(t *testing.T) {
	nvproxyOn := &config.Config{NVProxy: true}
	nvproxyOff := &config.Config{NVProxy: false}

	legacyHook := &specs.Spec{
		Process: &specs.Process{Env: []string{"NVIDIA_VISIBLE_DEVICES=0"}},
		Hooks: &specs.Hooks{
			Prestart: []specs.Hook{{Path: "/usr/bin/nvidia-container-runtime-hook"}},
		},
	}
	if !GPUFunctionalityNeedsSyntheticNvidiaDevices(legacyHook, nvproxyOn) {
		t.Error("legacy hook + no Linux.Devices: want synthetic devices")
	}

	csvLike := &specs.Spec{
		Process: &specs.Process{Env: []string{"NVIDIA_VISIBLE_DEVICES=all"}},
		Linux: &specs.Linux{
			Devices: []specs.LinuxDevice{{Path: "/dev/nvidiactl", Type: "c", Major: 195, Minor: 255}},
		},
	}
	if GPUFunctionalityNeedsSyntheticNvidiaDevices(csvLike, nvproxyOn) {
		t.Error("spec with /dev/nvidiactl: should not need synthetic devices")
	}

	if GPUFunctionalityNeedsSyntheticNvidiaDevices(legacyHook, nvproxyOff) {
		t.Error("nvproxy off: should not need synthetic devices")
	}

	noneWithHook := &specs.Spec{
		Process: &specs.Process{Env: []string{"NVIDIA_VISIBLE_DEVICES=none"}},
		Hooks: &specs.Hooks{
			Prestart: []specs.Hook{{Path: "/usr/bin/nvidia-container-runtime-hook"}},
		},
	}
	if !GPUFunctionalityNeedsSyntheticNvidiaDevices(noneWithHook, nvproxyOn) {
		t.Error("NVIDIA_VISIBLE_DEVICES=none + hook: still need synthetic nodes for driver-only path")
	}
}
