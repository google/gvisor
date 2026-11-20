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
