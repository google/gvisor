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

package kvm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
)

// sliceFromAddr returns a byte slice over the memory at [addr, addr+length).
func sliceFromAddr(addr, length uintptr) []byte {
	return unsafe.Slice(*(**byte)(unsafe.Pointer(&addr)), length)
}

// shadowVDSOVirt returns the host virtual address of the shadow [vdso], or
// zero if there is none.
func (m *machine) shadowVDSOVirt() uintptr {
	if len(m.shadowVDSO) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&m.shadowVDSO[0]))
}

// initShadowVDSO creates a binary-patched shadow copy of the host [vdso]
// when tscOffset != 0. In GR0 (guest ring 0 / guest EL1), hardware counter
// reads return Host_Counter + tscOffset, while the host [vvar] page contains
// raw Host_Counter base cycles. By patching counter reads in the shadow VDSO
// to subtract tscOffset, GR0 VDSO calls (such as Go runtime time.Now() /
// nanotime1) compute the exact unadjusted host time without any VM-exits.
//
// No shadow is needed if the guest cannot execute the host [vdso] at all: the
// Go runtime then issues the corresponding system calls, which trap to the
// host and are unaffected by the offset.
func (m *machine) initShadowVDSO() error {
	if m.tscOffset == 0 {
		return nil
	}
	var vdsoRegion virtualRegion
	found := false
	if err := applyVirtualRegions(func(vr virtualRegion) bool {
		if vr.filename == "[vdso]" {
			vdsoRegion = vr
			found = true
			return true
		}
		return false
	}); err != nil {
		return fmt.Errorf("error scanning /proc/self/maps for [vdso]: %v", err)
	}
	if !found || vdsoRegion.length == 0 {
		log.Infof("No [vdso] mapping; not creating a shadow [vdso] for the guest TSC offset")
		return nil
	}
	if excludeVirtualRegion(vdsoRegion) {
		log.Infof("[vdso] is not mapped into the KVM guest; not creating a shadow [vdso] for the guest TSC offset")
		return nil
	}

	addr, errno := hostsyscall.RawSyscall6(
		unix.SYS_MMAP,
		0,
		vdsoRegion.length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
		^uintptr(0),
		0)
	if errno != 0 {
		return fmt.Errorf("failed to allocate shadow VDSO memory: %v", errno)
	}
	shadowSlice := sliceFromAddr(addr, vdsoRegion.length)
	origSlice := sliceFromAddr(vdsoRegion.virtual, vdsoRegion.length)
	copy(shadowSlice, origSlice)

	if err := patchVDSOTSCOffset(shadowSlice, m.tscOffset); err != nil {
		hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, addr, vdsoRegion.length, 0)
		return fmt.Errorf("failed to patch shadow VDSO: %v", err)
	}

	m.shadowVDSO = shadowSlice
	m.vdsoVirt = vdsoRegion.virtual
	return nil
}

// protectShadowVDSO maps the shadow [vdso] read-only at its own host virtual
// address in the guest page tables, so that it is executable by the guest
// only through the [vdso] address it shadows.
func (m *machine) protectShadowVDSO() {
	if len(m.shadowVDSO) == 0 {
		return
	}
	shadowVirt := m.shadowVDSOVirt()
	length := uintptr(len(m.shadowVDSO))
	for length != 0 {
		physical, plength, ok := translateToPhysical(shadowVirt)
		if !ok || plength == 0 {
			panic(fmt.Sprintf("impossible translation: shadowVirt %x length %x", shadowVirt, length))
		}
		if plength > length {
			plength = length
		}
		m.kernel.PageTables.Map(
			hostarch.Addr(shadowVirt),
			plength,
			pagetables.MapOpts{AccessType: hostarch.Read},
			physical)
		m.mapPhysical(physical, plength)
		length -= plength
		shadowVirt += plength
	}
}

// destroyShadowVDSO releases the shadow [vdso], if any.
func (m *machine) destroyShadowVDSO() {
	if len(m.shadowVDSO) == 0 {
		return
	}
	addr := uintptr(unsafe.Pointer(&m.shadowVDSO[0]))
	length := uintptr(len(m.shadowVDSO))
	m.shadowVDSO = nil
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, addr, length, 0); errno != 0 {
		panic(fmt.Sprintf("error unmapping shadow VDSO: %v", errno))
	}
}
