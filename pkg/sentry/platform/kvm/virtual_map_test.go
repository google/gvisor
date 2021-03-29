// Copyright 2018 The gVisor Authors.
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

package kvm

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
)

type checker struct {
	ok         bool
	accessType hostarch.AccessType
}

func (c *checker) Containing(addr uintptr) func(virtualRegion) {
	c.ok = false // Reset for below calls.
	return func(vr virtualRegion) {
		if vr.virtual <= addr && addr < vr.virtual+vr.length {
			c.ok = true
			c.accessType = vr.accessType
		}
	}
}

func TestParseMaps(t *testing.T) {
	c := new(checker)

	// Simple test.
	if err := applyVirtualRegions(c.Containing(0)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MMap a new page.
	addr, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP, 0, hostarch.PageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANONYMOUS|unix.MAP_PRIVATE, 0, 0)
	if errno != 0 {
		t.Fatalf("unexpected map error: %v", errno)
	}

	// Re-parse maps.
	if err := applyVirtualRegions(c.Containing(addr)); err != nil {
		unix.RawSyscall(unix.SYS_MUNMAP, addr, hostarch.PageSize, 0)
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert that it now does contain the region.
	if !c.ok {
		unix.RawSyscall(unix.SYS_MUNMAP, addr, hostarch.PageSize, 0)
		t.Fatalf("updated map does not contain 0x%08x, expected true", addr)
	}

	// Map the region as PROT_NONE.
	newAddr, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP, addr, hostarch.PageSize,
		unix.PROT_NONE,
		unix.MAP_ANONYMOUS|unix.MAP_FIXED|unix.MAP_PRIVATE, 0, 0)
	if errno != 0 {
		t.Fatalf("unexpected map error: %v", errno)
	}
	if newAddr != addr {
		t.Fatalf("unable to remap address: got 0x%08x, wanted 0x%08x", newAddr, addr)
	}

	// Re-parse maps.
	if err := applyVirtualRegions(c.Containing(addr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.ok {
		t.Fatalf("final map does not contain 0x%08x, expected true", addr)
	}
	if c.accessType.Read || c.accessType.Write || c.accessType.Execute {
		t.Fatalf("final map has incorrect permissions for 0x%08x", addr)
	}

	// Unmap the region.
	unix.RawSyscall(unix.SYS_MUNMAP, addr, hostarch.PageSize, 0)
}
