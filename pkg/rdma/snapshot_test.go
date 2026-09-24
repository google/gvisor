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
