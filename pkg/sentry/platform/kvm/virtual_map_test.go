// Copyright 2018 Google Inc.
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
	"syscall"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type checker struct {
	ok bool
}

func (c *checker) Contains(addr uintptr) func(virtualRegion) {
	c.ok = false // Reset for below calls.
	return func(vr virtualRegion) {
		if vr.virtual <= addr && addr < vr.virtual+vr.length {
			c.ok = true
		}
	}
}

func TestParseMaps(t *testing.T) {
	c := new(checker)

	// Simple test.
	if err := applyVirtualRegions(c.Contains(0)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MMap a new page.
	addr, _, errno := syscall.RawSyscall6(
		syscall.SYS_MMAP, 0, usermem.PageSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE, 0, 0)
	if errno != 0 {
		t.Fatalf("unexpected map error: %v", errno)
	}

	// Re-parse maps.
	if err := applyVirtualRegions(c.Contains(addr)); err != nil {
		syscall.RawSyscall(syscall.SYS_MUNMAP, addr, usermem.PageSize, 0)
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert that it now does contain the region.
	if !c.ok {
		syscall.RawSyscall(syscall.SYS_MUNMAP, addr, usermem.PageSize, 0)
		t.Fatalf("updated map does not contain 0x%08x, expected true", addr)
	}

	// Unmap the region.
	syscall.RawSyscall(syscall.SYS_MUNMAP, addr, usermem.PageSize, 0)

	// Re-parse maps.
	if err := applyVirtualRegions(c.Contains(addr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert that it once again does _not_ contain the region.
	if c.ok {
		t.Fatalf("final map does contain 0x%08x, expected false", addr)
	}
}
