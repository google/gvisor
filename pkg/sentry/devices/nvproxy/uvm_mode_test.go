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

// Capabilities without UVM support must not issue queries that their seccomp
// filter forbids. A nil gofer makes an accidental query fail this test.
func TestUVMModeWithoutComputeUtility(t *testing.T) {
	for _, caps := range []nvconf.DriverCaps{0, nvconf.CapVideo, nvconf.CapGraphics} {
		got, err := UseApplicationMMUVM(nil, nil, []uint32{0}, caps)
		if got || err != nil {
			t.Errorf("caps %v: got (%t, %v), want (false, nil)", caps, got, err)
		}
	}
}
