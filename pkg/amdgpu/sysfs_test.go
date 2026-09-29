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

package amdgpu

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeTestSysfs creates a host sysfs with one CPU node and GPU nodes for
// renderD128 (gfx942) and renderD136 (gfx_target_version version).
func writeTestSysfs(t *testing.T, version string) string {
	t.Helper()
	root := t.TempDir()
	write := func(p, data string) {
		t.Helper()
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(p, target string) {
		t.Helper()
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	write("devices/virtual/kfd/kfd/dev", "510:0\n")
	write("devices/virtual/kfd/kfd/uevent", "MAJOR=510\nMINOR=0\nDEVNAME=kfd\n")
	write("devices/virtual/kfd/kfd/proc/1234/pasid", "secret\n")
	link("class/kfd/kfd", "../../devices/virtual/kfd/kfd")
	const top = "devices/virtual/kfd/kfd/topology"
	write(top+"/generation_id", "1\n")
	write(top+"/nodes/0/gpu_id", "0\n")
	write(top+"/nodes/0/properties", "cpu_cores_count 8\nsimd_count 0\ncapability 0\n")
	for i, gpu := range []struct{ minor, version, id string }{{"128", "90402", "123"}, {"136", version, "456"}} {
		base := top + "/nodes/" + string(rune('1'+i))
		write(base+"/gpu_id", gpu.id+"\n")
		write(base+"/properties", "simd_count 304\ndrm_render_minor "+gpu.minor+"\ngfx_target_version "+gpu.version+"\ncapability 134217729\n")
		write(base+"/caches/0/properties", "processor_id_low 0\n")
		if err := os.MkdirAll(filepath.Join(root, base, "p2p_links"), 0755); err != nil {
			t.Fatal(err)
		}
		pci := "devices/pci0000:00/0000:0" + string(rune('1'+i)) + ":00.0"
		write(pci+"/vendor", "0x1002\n")
		write(pci+"/resource0", "not an identity attribute")
		write(pci+"/drm/card"+string(rune('0'+i))+"/dev", "226:"+string(rune('0'+i))+"\n")
		write(pci+"/drm/card"+string(rune('0'+i))+"-DP-1/status", "disconnected\n")
		write(pci+"/drm/renderD"+gpu.minor+"/dev", "226:"+gpu.minor+"\n")
		write(pci+"/drm/renderD"+gpu.minor+"/uevent", "MAJOR=226\nMINOR="+gpu.minor+"\nDEVNAME=dri/renderD"+gpu.minor+"\n")
		link(pci+"/drm/renderD"+gpu.minor+"/device", "../..")
		link("class/drm/renderD"+gpu.minor, "../../"+pci+"/drm/renderD"+gpu.minor)
	}
	return root
}

func TestCollect(t *testing.T) {
	root := writeTestSysfs(t, "80003")
	snap, err := Collect(root, []Device{{Path: "/dev/kfd", Major: 510}, {Path: "/dev/dri/renderD128", Major: 226, Minor: 128}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.GPUIDs) != 1 || snap.GPUIDs[128] != 123 {
		t.Errorf("GPUIDs = %v, want {128: 123}", snap.GPUIDs)
	}
	const top = "devices/virtual/kfd/kfd/topology"
	for p, want := range map[string]string{
		top + "/nodes/0/properties":                          "cpu_cores_count 8\nsimd_count 0\ncapability 0\n",
		top + "/nodes/1/properties":                          "simd_count 304\ndrm_render_minor 128\ngfx_target_version 90402\ncapability 1\n",
		top + "/nodes/2/gpu_id":                              "456\n",
		top + "/nodes/2/caches/0/properties":                 "processor_id_low 0\n",
		"devices/pci0000:00/0000:01:00.0/vendor":             "0x1002\n",
		"devices/pci0000:00/0000:01:00.0/drm/renderD128/dev": "226:128\n",
	} {
		if got := snap.Files[p]; got != want {
			t.Errorf("Files[%q] = %q, want %q", p, got, want)
		}
	}
	for p, want := range map[string]string{
		"class/kfd/kfd":        "../../devices/virtual/kfd/kfd",
		"class/drm/renderD128": "../../devices/pci0000:00/0000:01:00.0/drm/renderD128",
		"dev/char/226:128":     "../../devices/pci0000:00/0000:01:00.0/drm/renderD128",
		"devices/pci0000:00/0000:01:00.0/drm/renderD128/device": "../..",
		"devices/pci0000:00/0000:01:00.0/driver":                "../../../bus/pci/drivers/amdgpu",
		"bus/pci/devices/0000:01:00.0":                          "../../../devices/pci0000:00/0000:01:00.0",
	} {
		if got := snap.Links[p]; got != want {
			t.Errorf("Links[%q] = %q, want %q", p, got, want)
		}
	}
	for _, p := range []string{"devices/pci0000:00/0000:01:00.0/drm/card0", top + "/nodes/1/p2p_links"} {
		if !slices.Contains(snap.Dirs, p) {
			t.Errorf("Dirs lacks %q", p)
		}
	}
	for p := range snap.Files {
		if strings.Contains(p, "/proc/") || strings.Contains(p, "resource0") || strings.Contains(p, "0000:02:00.0") {
			t.Errorf("unexpected file %q", p)
		}
	}
	for _, p := range snap.Dirs {
		if strings.Contains(p, "-DP-") {
			t.Errorf("unexpected directory %q", p)
		}
	}
}

func TestCollectRejectsUnqualifiedGPU(t *testing.T) {
	root := writeTestSysfs(t, "80003")
	devices := []Device{{Path: "/dev/kfd", Major: 510}, {Path: "/dev/dri/renderD128", Major: 226, Minor: 128}, {Path: "/dev/dri/renderD136", Major: 226, Minor: 136}}
	if _, err := Collect(root, devices); err == nil || !strings.Contains(err.Error(), "renderD136") {
		t.Errorf("Collect() error = %v, want gfx qualification failure for renderD136", err)
	}
	if _, err := Collect(writeTestSysfs(t, "90500"), devices); err != nil {
		t.Errorf("Collect() with gfx950 failed: %v", err)
	}
}
