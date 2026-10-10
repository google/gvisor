// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package kvm

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm/testutil"
)

func TestKernelTLS(t *testing.T) {
	bluepillTest(t, func(c *vCPU) {
		if !testutil.TLSWorks() {
			t.Errorf("tls does not work, and it should!")
		}
	})
}

// TestKernelNISV tests that Stage-2 faults without a valid instruction
// syndrome (_KVM_EXIT_ARM_NISV, triggered by e.g. LDP accessing a page mapped
// in Stage-1 but excluded from Stage-2 memslots such as [vvar]) inject an
// external data abort and immediately rerun the vCPU to cleanly transition
// back to host execution.
func TestKernelNISV(t *testing.T) {
	const (
		want0 = uint64(0x1122334455667788)
		want1 = uint64(0x99aabbccddeeff00)
		// _KVM_CAP_ARM_NISV_TO_USER causes KVM to exit with
		// KVM_EXIT_ARM_NISV instead of returning ENOSYS when a Stage-2 fault
		// has ESR_EL2.ISV == 0.
		_KVM_CAP_ARM_NISV_TO_USER = 177
	)
	type kvmEnableCap struct {
		cap   uint32
		flags uint32
		args  [4]uint64
		pad   [64]byte
	}

	kvmTest(t, func(k *KVM) {
		cap := kvmEnableCap{cap: _KVM_CAP_ARM_NISV_TO_USER}
		if _, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(k.machine.fd), KVM_ENABLE_CAP, uintptr(unsafe.Pointer(&cap))); errno != 0 {
			t.Fatalf("KVM_ENABLE_CAP(KVM_CAP_ARM_NISV_TO_USER) failed: %v", errno)
		}
	}, func(c *vCPU) bool {
		// ioeventfdMMIO.mapping is mapped in Stage-1 (m.kernel.PageTables) but
		// excluded from Stage-2 KVM memslots (pr.mmio == true). Temporarily make
		// it readable/writable on the host so that when LDP faults in Guest EL1
		// (triggering _KVM_EXIT_ARM_NISV -> ext_dabt -> VM exit to Host EL0), the
		// resumed LDP instruction succeeds in Host EL0.
		addr := ioeventfdMMIO.mapping
		mem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), hostarch.PageSize)
		if err := unix.Mprotect(mem, unix.PROT_READ|unix.PROT_WRITE); err != nil {
			t.Fatalf("mprotect failed: %v", err)
		}
		defer unix.Mprotect(mem, unix.PROT_NONE)

		binary.NativeEndian.PutUint64(mem[0:8], want0)
		binary.NativeEndian.PutUint64(mem[8:16], want1)

		for i := 0; i < 10; i++ {
			bluepill(c)
			got0, got1 := testutil.LoadPair(addr)
			if got := c.state.Load(); got != vCPUUser {
				t.Fatalf("iter %d: vCPU state after NISV fault = %v, want %v", i, got, vCPUUser)
			}
			if got0 != want0 || got1 != want1 {
				t.Fatalf("iter %d: LoadPair(%#x) = (%#x, %#x), want (%#x, %#x)", i, addr, got0, got1, want0, want1)
			}
		}
		return false
	})
}

// TestApplicationPAC checks that non-hint pointer authentication
// instructions work in guest user mode. On hosts with FEAT_PAuth, these
// instructions execute natively (Linux enables pointer authentication for
// all user tasks), so applications compiled for armv8.3+ may execute them
// unconditionally; they must not be treated as undefined instructions.
func TestApplicationPAC(t *testing.T) {
	applicationTest(t, true, testutil.AddrOfPACLoop(), func(c *vCPU, regs *arch.Registers, pt *pagetables.PageTables) bool {
		if !hasPtrauth {
			// Without FEAT_PAuth, PAC instructions are UNDEFINED and
			// SIGILL is the correct native behavior: nothing to test.
			t.Skip("pointer authentication is not supported by the host")
		}
		var si linux.SignalInfo
		if _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: &dummyFPState,
			PageTables:         pt,
		}, &si); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != nil {
			t.Errorf("PAC instructions raised (%v, %+v), expected a clean syscall return", err, si)
		}
		return false
	})
}

// TestKernelFaultOnUnmappedSP verifies that an EL1 data abort occurring when
// SP_EL1 (RSP) points to a page unmapped in Guest EL1 TTBR0_EL1 cleanly exits
// to Host EL0 without triggering a recursive fault in KERNEL_ENTRY_FROM_EL1,
// and preserves R18 and R19 across the exception and VM exit.
func TestKernelFaultOnUnmappedSP(t *testing.T) {
	const (
		wantR18 = uintptr(0xdeadbeefcafebabe)
		wantR19 = uintptr(0x123456789abcdef0)
	)

	mem, err := unix.Mmap(-1, 0, hostarch.PageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANONYMOUS|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap failed: %v", err)
	}
	defer unix.Munmap(mem)

	pageAddr := uintptr(unsafe.Pointer(&mem[0]))
	phys, length, ok := translateToPhysical(pageAddr)
	if !ok || length < hostarch.PageSize {
		t.Fatalf("translateToPhysical(%#x) = (%#x, %#x, %v), want ok with length >= %#x", pageAddr, phys, length, ok, hostarch.PageSize)
	}

	kvmTest(t, nil, func(c *vCPU) bool {
		// Unmap pageAddr from the guest EL1 kernel page tables (TTBR0_EL1)
		// while keeping it mapped in the host process.
		c.machine.kernel.PageTables.Unmap(hostarch.Addr(pageAddr), hostarch.PageSize)
		defer c.machine.kernel.PageTables.Map(
			hostarch.Addr(pageAddr),
			hostarch.PageSize,
			pagetables.MapOpts{AccessType: hostarch.ReadWrite},
			phys,
		)

		sp := pageAddr + hostarch.PageSize - 16
		bluepill(c)
		ring0.FlushTlbAll()

		gotR18, gotR19 := testutil.StorePairAtSP(sp, wantR18, wantR19)
		if got := c.state.Load(); got != vCPUUser {
			t.Fatalf("vCPU state after EL1 fault on unmapped SP = %v, want %v", got, vCPUUser)
		}
		if gotR18 != wantR18 || gotR19 != wantR19 {
			t.Fatalf("StorePairAtSP R18/R19 = (%#x, %#x), want (%#x, %#x)", gotR18, gotR19, wantR18, wantR19)
		}
		stored0 := uintptr(binary.NativeEndian.Uint64(mem[hostarch.PageSize-16 : hostarch.PageSize-8]))
		stored1 := uintptr(binary.NativeEndian.Uint64(mem[hostarch.PageSize-8 : hostarch.PageSize]))
		if stored0 != wantR18 || stored1 != wantR19 {
			t.Fatalf("stored pair at SP = (%#x, %#x), want (%#x, %#x)", stored0, stored1, wantR18, wantR19)
		}
		return false
	})
}

// TestTopUserPageMapped verifies that MaximumUserAddress covers the full
// 48-bit user address space up to UserspaceSize (including the top page at
// [0x0000fffffffff000, 0x0001000000000000) where Linux ARM64 places the
// initial thread stack).
func TestTopUserPageMapped(t *testing.T) {
	if ring0.MaximumUserAddress != ring0.UserspaceSize {
		t.Fatalf("ring0.MaximumUserAddress = %#x, want %#x", ring0.MaximumUserAddress, ring0.UserspaceSize)
	}
	const topPage = ring0.UserspaceSize - hostarch.PageSize
	kvmTest(t, nil, func(c *vCPU) bool {
		// Check whether the top page is present in a non-excluded VMA (such as [stack]).
		var topPageMappedInHost bool
		_ = applyVirtualRegions(func(vr virtualRegion) bool {
			if vr.virtual <= topPage && topPage < vr.virtual+vr.length && !excludeVirtualRegion(vr) {
				topPageMappedInHost = true
				return true
			}
			return false
		})
		if !topPageMappedInHost {
			return false
		}
		if _, _, ok := translateToPhysical(topPage); !ok {
			t.Fatalf("top user page %#x is mapped on host but missing from physicalRegions", topPage)
		}
		if _, _, size, _ := c.machine.kernel.PageTables.Lookup(hostarch.Addr(topPage), false); size == 0 {
			t.Fatalf("top user page %#x is missing from kernel PageTables (TTBR0_EL1)", topPage)
		}
		return false
	})
}
