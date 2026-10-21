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

package nvproxy

import (
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

func TestGPURequiresApplicationMMUVM(t *testing.T) {
	for _, test := range []struct {
		name       string
		arch, impl uint32
		want       bool
	}{
		{"GH100 discrete", 0x180, 0, false},
		{"GH100 SOC", 0x180, 1, true},
		{"GB100", 0x1a0, 0, true},
		{"GB110", 0x1a0, 3, true},
		{"unknown GB100 implementation", 0x1a0, 1, false},
		{"GB202", 0x1b0, 2, false},
		{"GR100", 0x1c0, 0, true},
		{"unknown GR100 implementation", 0x1c0, 1, false},
		{"unknown architecture", 0xffffffff, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := gpuRequiresApplicationMMUVM(nvconf.GPUArchInfo{Architecture: test.arch, Implementation: test.impl}); got != test.want {
				t.Errorf("architecture %#x implementation %#x: got %t, want %t", test.arch, test.impl, got, test.want)
			}
		})
	}
}

func TestApplicationMMUVMDriverVersion(t *testing.T) {
	gh100 := nvconf.GPUArchInfo{Architecture: 0x180, Implementation: 0}
	gh100SOC := nvconf.GPUArchInfo{Architecture: 0x180, Implementation: 1}
	for _, gpu := range []struct {
		name     string
		arches   []nvconf.GPUArchInfo
		requires bool
	}{
		{"no GPUs", nil, false},
		{"GH100 discrete", []nvconf.GPUArchInfo{gh100}, false},
		{"GH100 SOC", []nvconf.GPUArchInfo{gh100SOC}, true},
		{"GB100", []nvconf.GPUArchInfo{{Architecture: 0x1a0, Implementation: 0}}, true},
		{"GB110", []nvconf.GPUArchInfo{{Architecture: 0x1a0, Implementation: 3}}, true},
		{"GB202", []nvconf.GPUArchInfo{{Architecture: 0x1b0, Implementation: 2}}, false},
		{"GR100", []nvconf.GPUArchInfo{{Architecture: 0x1c0, Implementation: 0}}, true},
		{"discrete then SOC", []nvconf.GPUArchInfo{gh100, gh100SOC}, true},
		{"SOC then discrete", []nvconf.GPUArchInfo{gh100SOC, gh100}, true},
	} {
		for _, driver := range []struct {
			version   nvconf.DriverVersion
			supported bool
		}{
			{nvconf.NewDriverVersion(535, 104, 5), false},
			{nvconf.NewDriverVersion(535, 309, 1), false},
			{nvconf.NewDriverVersion(545, 23, 6), false},
			{nvconf.NewDriverVersion(550, 40, 6), false},
			{nvconf.NewDriverVersion(550, 40, 7), true},
			{nvconf.NewDriverVersion(550, 40, 8), true},
			{nvconf.NewDriverVersion(580, 65, 6), true},
		} {
			t.Run(gpu.name+"/"+driver.version.String(), func(t *testing.T) {
				got, err := applicationMMUVMForGPUs(gpu.arches, driver.version)
				want := gpu.requires && driver.supported
				wantErr := gpu.requires && !driver.supported
				if got != want || (err != nil) != wantErr {
					t.Fatalf("applicationMMUVMForGPUs(%v, %v) = (%t, %v), want (%t, error=%t)", gpu.arches, driver.version, got, err, want, wantErr)
				}
				if wantErr && (!strings.Contains(err.Error(), "550.40.07") || !strings.Contains(err.Error(), driver.version.String())) {
					t.Errorf("error %q does not identify the required and configured driver versions", err)
				}
			})
		}
	}
}

// Capabilities without UVM support must not issue queries that their seccomp
// filter forbids. A nil gofer makes an accidental query fail this test.
func TestUVMModeWithoutComputeUtility(t *testing.T) {
	for _, caps := range []nvconf.DriverCaps{0, nvconf.CapVideo, nvconf.CapGraphics} {
		got, err := UseApplicationMMUVM(nil, nil, []uint32{0}, caps, nvconf.NewDriverVersion(535, 104, 5))
		if got || err != nil {
			t.Errorf("caps %v: got (%t, %v), want (false, nil)", caps, got, err)
		}
	}
}

func TestUVMModeWithoutGPUs(t *testing.T) {
	got, err := UseApplicationMMUVM(nil, nil, nil, compUtil, nvconf.NewDriverVersion(535, 104, 5))
	if got || err != nil {
		t.Errorf("got (%t, %v), want (false, nil)", got, err)
	}
}

func TestUVMModeOnNonARM64(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("application-mm UVM is enabled on arm64")
	}
	got, err := UseApplicationMMUVM(nil, nil, []uint32{0}, compUtil, nvconf.NewDriverVersion(535, 104, 5))
	if got || err != nil {
		t.Errorf("got (%t, %v), want (false, nil)", got, err)
	}
}
