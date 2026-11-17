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

package rdma

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCollectNCCLMergePaths(t *testing.T) {
	sysRoot := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		p := filepath.Join(sysRoot, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	addNIC := func(uverbs string, minor int64, ibdev, leaf string) UverbsSpec {
		t.Helper()
		write(leaf+"/uevent", "DRIVER=mlx5_core\n")
		write("class/infiniband_verbs/"+uverbs+"/dev", fmt.Sprintf("231:%d\n", minor))
		write("class/infiniband_verbs/"+uverbs+"/ibdev", ibdev+"\n")
		write("class/infiniband_verbs/"+uverbs+"/abi_version", "1\n")
		write("class/infiniband/"+ibdev+"/ports/1/gids/0", "fe80::1\n")
		if err := os.Symlink(filepath.Join(sysRoot, leaf), filepath.Join(sysRoot, "class/infiniband", ibdev, "device")); err != nil {
			t.Fatal(err)
		}
		return UverbsSpec{Name: uverbs, Major: 231, Minor: minor}
	}
	write("class/infiniband_verbs/abi_version", "6\n")

	// A VM that places NICs and other devices directly on a root bus
	// whose slot 0 is a host bridge.
	const hostBridge = "devices/pci0002:00/0002:00:00.0"
	write(hostBridge+"/class", "0x060000\n")
	write(hostBridge+"/vendor", "0x8086\n")
	write(hostBridge+"/uevent", "PCI_CLASS=60000\n")
	write(hostBridge+"/config", "host bridge config")
	write("devices/pci0002:00/0002:00:05.0/class", "0x010802\n")
	vfNIC := addNIC("uverbs5", 5, "mlx5_5", "devices/pci0002:00/0002:00:09.0")

	// Port 1 of a two-port NIC whose port 0 is not in the spec.
	const port0 = "devices/pci0000:3a/0000:3a:00.0/0000:3b:00.0"
	write(port0+"/class", "0x020700\n")
	write("devices/pci0000:3a/0000:3a:00.0/0000:3b:00.2/class", "0x020700\n")
	port1NIC := addNIC("uverbs1", 1, "mlx5_1", "devices/pci0000:3a/0000:3a:00.0/0000:3b:00.1")

	// A NIC on a bus with no function at slot 0.
	soloNIC := addNIC("uverbs2", 2, "mlx5_2", "devices/pci0001:00/0001:00:02.0")

	snap, err := Collect(sysRoot, []UverbsSpec{vfNIC, port1NIC, soloNIC})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, n := range snap.PCINodes {
		paths = append(paths, n.Path)
		if n.Path == hostBridge {
			wantAttrs := map[string]string{
				"class":  "0x060000\n",
				"vendor": "0x8086\n",
				"uevent": "PCI_CLASS=60000\n",
			}
			if !reflect.DeepEqual(n.Attrs, wantAttrs) || string(n.Config) != "host bridge config" {
				t.Errorf("host bridge node = %+v, want attrs %v and its config", n, wantAttrs)
			}
		}
	}
	wantPaths := []string{
		"devices/pci0000:3a",
		"devices/pci0000:3a/0000:3a:00.0",
		port0,
		"devices/pci0000:3a/0000:3a:00.0/0000:3b:00.1",
		"devices/pci0001:00",
		"devices/pci0001:00/0001:00:02.0",
		"devices/pci0002:00",
		hostBridge,
		"devices/pci0002:00/0002:00:09.0",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Errorf("PCI node paths = %v, want %v", paths, wantPaths)
	}
}

func TestCollectGPUs(t *testing.T) {
	sysRoot := t.TempDir()
	const (
		bridge     = "devices/pci0000:16/0000:16:01.0"
		gpu        = bridge + "/0000:17:00.0"
		gpu2       = bridge + "/0000:17:01.0"
		nvswitch   = "devices/pci0000:16/0000:16:02.0"
		vfioGPU    = "devices/pci0000:80/0000:80:01.0/0000:81:00.0"
		unboundGPU = "devices/pci0000:80/0000:80:02.0/0000:82:00.0"
		bmcVGA     = "devices/pci0000:00/0000:00:1c.0/0000:02:00.0"
	)
	config := strings.Repeat("c", 256)
	bridgeConfig := strings.Repeat("b", 4096)
	wantGPUAttrs := map[string]string{
		"class":            "0x030200\n",
		"vendor":           "0x10de\n",
		"device":           "0x2329\n",
		"subsystem_vendor": "0x10de\n",
		"subsystem_device": "0x198b\n",
		"revision":         "0xa1\n",
		"numa_node":        "1\n",
		"local_cpus":       "ffff0000\n",
		"local_cpulist":    "16-31\n",
		"max_link_speed":   "8.0 GT/s PCIe\n",
		"max_link_width":   "16\n",
		"modalias":         "pci:v000010DEd00002329sv000010DEsd0000198Bbc03sc02i00\n",
		"resource":         "0x0000000000000000 0x0000000000000000 0x0000000000000000\n",
	}
	// No class/infiniband_verbs: collecting GPU topology reads no RDMA state.
	files := map[string]string{
		bridge + "/class":                        "0x060400\n",
		bridge + "/config":                       bridgeConfig,
		gpu + "/config":                          config,
		gpu + "/uevent":                          "DRIVER=nvidia\n",
		gpu + "/current_link_speed":              "2.5 GT/s PCIe\n",
		gpu + "/current_link_width":              "16\n",
		gpu2 + "/class":                          "0x030000\n",
		gpu2 + "/vendor":                         "0x10de\n",
		nvswitch + "/class":                      "0x068000\n",
		nvswitch + "/vendor":                     "0x10de\n",
		vfioGPU + "/class":                       "0x030200\n",
		vfioGPU + "/vendor":                      "0x10de\n",
		unboundGPU + "/class":                    "0x030200\n",
		unboundGPU + "/vendor":                   "0x10de\n",
		bmcVGA + "/class":                        "0x030000\n",
		bmcVGA + "/vendor":                       "0x1a03\n",
		"devices/pci0000:16/uevent":              "",
		"bus/pci/drivers/nvidia/bind":            "",
		"bus/pci/drivers/nvidia-nvswitch/new_id": "",
		"devices/system/node/has_cpu":            "0-1\n",
		"devices/system/node/online":             "0-1\n",
	}
	for name, val := range wantGPUAttrs {
		files[gpu+"/"+name] = val
	}
	writeTestFiles(t, sysRoot, files)
	for driver, fns := range map[string][]string{
		"nvidia":               {gpu, gpu2, bmcVGA},
		"nvidia-nvswitch":      {nvswitch},
		"nvgrace_gpu_vfio_pci": {vfioGPU},
	} {
		dir := filepath.Join(sysRoot, "bus/pci/drivers", driver)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for _, fn := range fns {
			if err := os.Symlink(filepath.Join(sysRoot, fn), filepath.Join(dir, filepath.Base(fn))); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A function that was unbound after its driver directory was listed.
	if err := os.Symlink(filepath.Join(sysRoot, "devices/pci0000:16/0000:16:03.0"), filepath.Join(sysRoot, "bus/pci/drivers/nvidia/0000:16:03.0")); err != nil {
		t.Fatal(err)
	}

	// Only the NVIDIA GPUs and NVSwitch that are bound to an NVIDIA driver
	// are leaves, and the GPUs share their ancestors.
	snap, err := CollectGPUs(sysRoot, "0x10de", []string{"nvidia", "nvidia-nvswitch"})
	if err != nil {
		t.Fatalf("CollectGPUs failed: %v", err)
	}
	if snap == nil {
		t.Fatal("CollectGPUs returned no snapshot")
	}
	var paths []string
	for _, n := range snap.PCINodes {
		paths = append(paths, n.Path)
		switch n.Path {
		case "devices/pci0000:16":
			if len(n.Attrs) != 0 || n.Config != nil {
				t.Errorf("root complex has attributes %v and config %q, want none", n.Attrs, n.Config)
			}
		case bridge:
			if string(n.Config) != bridgeConfig[:64] {
				t.Errorf("bridge config = %q, want its header", n.Config)
			}
		case gpu:
			if string(n.Config) != config[:64] {
				t.Errorf("GPU config = %q, want its header", n.Config)
			}
			if !reflect.DeepEqual(n.Attrs, wantGPUAttrs) {
				t.Errorf("GPU attributes = %v, want %v", n.Attrs, wantGPUAttrs)
			}
		}
	}
	if want := []string{"devices/pci0000:16", bridge, gpu, gpu2, nvswitch}; !reflect.DeepEqual(paths, want) {
		t.Errorf("PCI node paths = %v, want %v", paths, want)
	}
	if snap.VerbsABIVersion != "" || len(snap.Devices) != 0 {
		t.Errorf("got verbs ABI version %q and %d devices, want none", snap.VerbsABIVersion, len(snap.Devices))
	}
	if snap.NUMA == nil || !reflect.DeepEqual(snap.NUMA.Aggregate, map[string]string{"has_cpu": "0-1\n", "online": "0-1\n"}) {
		t.Errorf("NUMA = %+v, want the host's NUMA nodes", snap.NUMA)
	}

	if snap, err := CollectGPUs(sysRoot, "0x1002", []string{"amdgpu"}); snap != nil || err != nil {
		t.Errorf("CollectGPUs for a vendor without GPUs = %+v, %v, want nil, nil", snap, err)
	}
}
