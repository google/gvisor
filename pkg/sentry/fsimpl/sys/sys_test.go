// Copyright 2024 The gVisor Authors.
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

package sys

import (
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func TestFullCPUMask(t *testing.T) {
	for _, test := range []struct {
		cores uint
		want  string
	}{
		{1, "1"},
		{2, "3"},
		{3, "7"},
		{4, "f"},
		{5, "1f"},
		{32, "ffffffff"},
		{33, "1,ffffffff"},
		{36, "f,ffffffff"},
		{37, "1f,ffffffff"},
		{64, "ffffffff,ffffffff"},
		{65, "1,ffffffff,ffffffff"},
	} {
		if got := fullCPUMask(test.cores); got != test.want {
			t.Errorf("fullCPUMask(%d): got %s, want %s", test.cores, got, test.want)
		}
	}
}

func TestOneCPUMask(t *testing.T) {
	for _, test := range []struct {
		i     uint
		cores uint
		want  string
	}{
		{0, 1, "1"},
		{0, 4, "1"},
		{1, 4, "2"},
		{2, 4, "4"},
		{3, 4, "8"},
		{0, 5, "01"},
		{4, 5, "10"},
		{0, 32, "00000001"},
		{26, 32, "04000000"},
		{0, 33, "0,00000001"},
		{31, 33, "0,80000000"},
		{32, 33, "1,00000000"},
		{0, 64, "00000000,00000001"},
		{31, 64, "00000000,80000000"},
		{32, 64, "00000001,00000000"},
		{63, 64, "80000000,00000000"},
		{0, 65, "0,00000000,00000001"},
		{31, 65, "0,00000000,80000000"},
		{32, 65, "0,00000001,00000000"},
		{63, 65, "0,80000000,00000000"},
		{64, 65, "1,00000000,00000000"},
	} {
		if got := oneCPUMask(test.i, test.cores); got != test.want {
			t.Errorf("oneCPUMask(%d, %d): got %s, want %s", test.i, test.cores, got, test.want)
		}
	}
}

func TestIsCPUDirName(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{"cpu0", true},
		{"cpu12", true},
		{"cpu", false},
		{"cpufreq", false},
		{"cpuidle", false},
		{"cpu1a", false},
		{"online", false},
		{"xcpu0", false},
	} {
		if got := isCPUDirName(test.name); got != test.want {
			t.Errorf("isCPUDirName(%q): got %t, want %t", test.name, got, test.want)
		}
	}
}

// TestCPUDirLookup checks that /sys/devices/system/cpu only creates the cpuN
// directories when one of them is looked up.
func TestCPUDirLookup(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	const cores = 4
	d := (&filesystem{}).newLazyCPURootDir(ctx, creds, cores)
	defer d.DecRef(ctx)

	if got, want := d.Links(), uint32(2+cores); got != want {
		t.Errorf("link count: got %d, want %d", got, want)
	}
	for _, name := range []string{"online", "possible", "present"} {
		inode, err := d.Lookup(ctx, name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		inode.DecRef(ctx)
	}
	if _, err := d.Lookup(ctx, "cpufreq"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("Lookup(cpufreq): got error %v, want ENOENT", err)
	}
	if d.populated.Load() {
		t.Errorf("directory is populated after lookups of non-cpuN names")
	}

	inode, err := d.Lookup(ctx, "cpu3")
	if err != nil {
		t.Fatalf("Lookup(cpu3): %v", err)
	}
	inode.DecRef(ctx)
	if !d.populated.Load() {
		t.Errorf("directory is not populated after lookup of cpu3")
	}
	if _, err := d.Lookup(ctx, "cpu4"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("Lookup(cpu4): got error %v, want ENOENT", err)
	}
}
