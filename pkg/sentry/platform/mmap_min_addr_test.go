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

package platform

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// dacMMapMinAddr returns the DAC component of the mmap address limit from
// procfs. The limit the kernel enforces is at least this (an LSM may raise
// it further).
func dacMMapMinAddr(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile(systemMMapMinAddrSource)
	if err != nil {
		t.Skipf("cannot read %s: %v", systemMMapMinAddrSource, err)
	}
	val, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", systemMMapMinAddrSource, err)
	}
	return val
}

func TestProbeMMapMinAddr(t *testing.T) {
	probed, err := probeMMapMinAddr()
	if err != nil {
		t.Fatalf("probeMMapMinAddr() failed: %v", err)
	}
	t.Logf("probed minimum mappable address: %#x", probed)
	if probed%hostarch.PageSize != 0 {
		t.Errorf("probed value %#x is not page-aligned", probed)
	}
	// The probed address must itself be mappable...
	if ok, err := mmapProbe(uintptr(probed)); err != nil {
		t.Fatalf("mmapProbe(%#x) failed: %v", probed, err)
	} else if !ok {
		t.Errorf("probed value %#x is not mappable", probed)
	}
	// ... and the page below it must not be, i.e. probed is the boundary.
	if probed > 0 {
		below := probed - hostarch.PageSize
		if ok, err := mmapProbe(uintptr(below)); err != nil {
			t.Fatalf("mmapProbe(%#x) failed: %v", below, err)
		} else if ok {
			t.Errorf("%#x is mappable, but probe returned %#x as the minimum", below, probed)
		}
	}
	// The enforced limit is never below the DAC component from procfs.
	if dac := dacMMapMinAddr(t); probed < dac {
		t.Errorf("probed value %#x is below vm.mmap_min_addr %#x", probed, dac)
	} else if probed != dac {
		t.Logf("probed value %#x exceeds vm.mmap_min_addr %#x (LSM restriction, or non-page-aligned sysctl value)", probed, dac)
	}
}

func TestSystemMMapMinAddrMatchesProcfs(t *testing.T) {
	// On hosts where the file is readable, the lazy initializer must use it
	// verbatim.
	if dac, got := dacMMapMinAddr(t), uint64(SystemMMapMinAddr()); got != dac {
		t.Errorf("SystemMMapMinAddr() = %#x, want vm.mmap_min_addr value %#x", got, dac)
	}
}
