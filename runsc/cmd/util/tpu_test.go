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

package util

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/tpu"
)

func TestTPUVFIODeviceValid(t *testing.T) {
	// IOMMU group 5 holds a single TPU v5e PCI function.
	iommuGroupsDir := t.TempDir()
	devDir := filepath.Join(iommuGroupsDir, "5", "devices", "0000:00:04.0")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", devDir, err)
	}
	for name, val := range map[string]uint64{vendorFile: googleVendorID, deviceFile: tpu.TPUV5eDeviceID} {
		if err := os.WriteFile(filepath.Join(devDir, name), []byte(fmt.Sprintf("0x%04x\n", val)), 0644); err != nil {
			t.Fatalf("WriteFile(%q): %v", name, err)
		}
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "vfio group", path: "/dev/vfio/5", want: true},
		{name: "dotdot to sysfs group", path: "/dev/vfio/../../sys/kernel/iommu_groups/5", want: false},
		{name: "other dir with group basename", path: "/etc/5", want: false},
		{name: "dotdot within vfio", path: "/dev/vfio/../vfio/5", want: false},
		{name: "trailing slash", path: "/dev/vfio/5/", want: false},
		{name: "vfio container", path: "/dev/vfio/vfio", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got, err := tpuVFIODeviceValidIn(iommuGroupsDir, tst.path)
			if tst.want && err != nil {
				t.Fatalf("tpuVFIODeviceValidIn(%q) failed: %v", tst.path, err)
			}
			if got != tst.want {
				t.Errorf("tpuVFIODeviceValidIn(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}
