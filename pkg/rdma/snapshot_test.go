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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestSafeName(t *testing.T) {
	for name, want := range map[string]bool{
		"uverbs0":      true,
		"mlx5_0":       true,
		"0000:0c:00.0": true,
		"eth0.100":     true,
		"enp12s0f0np0": true,
		"a.b":          true,
		"0":            true,
		"":             false,
		".":            false,
		"..":           false,
		".hidden":      false,
		"-flag":        false,
		"_x":           false,
		"a/b":          false,
		"a b":          false,
		"a\n":          false,
		"a\x00b":       false,
	} {
		if got := SafeName(name); got != want {
			t.Errorf("SafeName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsBDF(t *testing.T) {
	for name, want := range map[string]bool{
		"0000:0c:00.0": true,
		"0000:ff:1f.7": true,
		// Synthetic domains above 0xffff (e.g. Intel VMD) print wider than
		// %04x.
		"10000:e0:06.0": true,
		"0000:0c:00":    false,
		"0000:0c:00.8":  false, // function is 0-7
		"0000:0C:00.0":  false, // the kernel prints lowercase hex
		"000:0c:00.0":   false,
		"pci0000:0c":    false,
		"0000:0c:00.0/": false,
	} {
		if got := IsBDF(name); got != want {
			t.Errorf("IsBDF(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPCIRootRE(t *testing.T) {
	for name, want := range map[string]bool{
		"pci0000:07":    true,
		"pci10000:e0":   true,
		"pci0000":       false,
		"0000:07":       false,
		"pci0000:07:00": false,
		"pci0000:0G":    false,
	} {
		if got := pciRootRE.MatchString(name); got != want {
			t.Errorf("pciRootRE.MatchString(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAddWithAncestors(t *testing.T) {
	for _, tc := range []struct {
		leaf string
		want []string // nil means an error is expected
	}{
		{
			leaf: "devices/pci0000:07/0000:07:01.0/0000:0c:00.0",
			want: []string{
				"devices/pci0000:07",
				"devices/pci0000:07/0000:07:01.0",
				"devices/pci0000:07/0000:07:01.0/0000:0c:00.0",
			},
		},
		{
			leaf: "devices/pci10000:e0/10000:e0:06.0",
			want: []string{
				"devices/pci10000:e0",
				"devices/pci10000:e0/10000:e0:06.0",
			},
		},
		{leaf: "devices/pci0000:07/virtual0/0000:0c:00.0", want: nil},
		{leaf: "sys/devices/pci0000:07", want: nil},
	} {
		set := make(map[string]bool)
		err := addWithAncestors(set, tc.leaf)
		if tc.want == nil {
			if err == nil {
				t.Errorf("addWithAncestors(%q) succeeded, want error", tc.leaf)
			}
			continue
		}
		if err != nil {
			t.Errorf("addWithAncestors(%q) failed: %v", tc.leaf, err)
			continue
		}
		var got []string
		for p := range set {
			got = append(got, p)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("addWithAncestors(%q) = %v, want %v", tc.leaf, got, tc.want)
		}
	}
}

func writeTestFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", p, err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile(%q): %v", p, err)
		}
	}
}

func TestCollectPorts(t *testing.T) {
	sysRoot := t.TempDir()
	const nicLeaf = "devices/pci0000:07/0000:07:01.0/0000:0c:00.0"
	writeTestFiles(t, sysRoot, map[string]string{
		"class/infiniband_verbs/abi_version":               "6\n",
		"class/infiniband_verbs/uverbs0/dev":               "231:192\n",
		"class/infiniband_verbs/uverbs0/ibdev":             "mlx5_0\n",
		"class/infiniband_verbs/uverbs0/abi_version":       "1\n",
		nicLeaf + "/uevent":                                "DRIVER=mlx5_core\n",
		"class/infiniband/mlx5_0/node_guid":                "0011:2233:4455:6677\n",
		"class/infiniband/mlx5_0/ports/1/link_layer":       "InfiniBand\n",
		"class/infiniband/mlx5_0/ports/1/gids/0":           "",
		"class/infiniband/mlx5_0/ports/1/pkeys/0":          "0xffff\n",
		"class/infiniband/mlx5_0/ports/1/pkeys/1":          "0x0000\n",
		"class/infiniband/mlx5_0/ports/1/counters/rcv_pkt": "",
		"class/infiniband/mlx5_0/ports/2/link_layer":       "Ethernet\n",
		"class/infiniband/mlx5_0/ports/2/gids/0":           "",
	})
	if err := os.Symlink(filepath.Join(sysRoot, nicLeaf), filepath.Join(sysRoot, "class/infiniband/mlx5_0/device")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	uverbs := []UverbsSpec{{Name: "uverbs0", Major: 231, Minor: 192}}
	snap, err := Collect(sysRoot, uverbs)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(snap.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(snap.Devices))
	}
	ports := snap.Devices[0].Ports
	if got, want := ports["1"].PKeyNames, []string{"0", "1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("port 1 PKeyNames = %v, want %v", got, want)
	}
	if got := ports["2"].PKeyNames; got != nil {
		t.Errorf("port 2 PKeyNames = %v, want nil", got)
	}

	// Replace port 2's missing pkeys directory with a regular file so ReadDir
	// fails with ENOTDIR, verifying non-ENOENT errors are surfaced.
	if err := os.WriteFile(filepath.Join(sysRoot, "class/infiniband/mlx5_0/ports/2/pkeys"), nil, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Collect(sysRoot, uverbs); err == nil {
		t.Errorf("Collect succeeded with non-directory pkeys, want error")
	}
}
