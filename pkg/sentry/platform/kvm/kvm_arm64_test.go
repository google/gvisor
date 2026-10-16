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
	"fmt"
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

// TestKernelTopUserPageStack tests that the top user page
// [UserspaceSize-PageSize, UserspaceSize) is mapped in the kernel page tables
// and KVM memslots on ARM64.
func TestKernelTopUserPageStack(t *testing.T) {
	for _, page := range []uintptr{
		ring0.UserspaceSize - 2*hostarch.PageSize,
		ring0.UserspaceSize - hostarch.PageSize,
	} {
		addr, errno := hostsyscall.RawSyscall6(
			unix.SYS_MMAP,
			page,
			hostarch.PageSize,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|linux.MAP_FIXED_NOREPLACE,
			0, 0)
		if errno == unix.EEXIST {
			// Already covered by [stack] (e.g. when ASLR is disabled).
			continue
		}
		if errno != 0 {
			t.Fatalf("mmap(%#x) failed: %v", page, errno)
		}
		defer hostsyscall.RawSyscall(unix.SYS_MUNMAP, addr, hostarch.PageSize, 0)
	}

	bluepillTest(t, func(c *vCPU) {
		const want = uint64(0xfeedfacecafebeef)
		if got := testutil.TouchStackAt(ring0.UserspaceSize); got != want {
			t.Fatalf("TouchStackAt(%#x) = %#x, want %#x", ring0.UserspaceSize, got, want)
		}
		if got := c.state.Load(); got != vCPUUser|vCPUGuest {
			t.Fatalf("vCPU state after TouchStackAt = %v, want %v", got, vCPUUser|vCPUGuest)
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

// disallowedVDSOExit returns a description of the last guest exit of c and
// whether it indicates that a vDSO time call did not run entirely in guest
// mode: a system call that reads the time.
//
// A guest kernel system call saves the system call number in Regs[8].
// Exceptions at EL1 do not record their vector in the CPU state, so unlike on
// amd64 they cannot be told apart from system calls here.
func disallowedVDSOExit(c *vCPU) (string, bool) {
	regs := c.CPU.Registers()
	switch sysno := regs.Regs[8]; sysno {
	case unix.SYS_CLOCK_GETTIME, unix.SYS_GETTIMEOFDAY:
		return fmt.Sprintf("time system call %d at pc %#x", sysno, regs.Pc), true
	default:
		return fmt.Sprintf("system call %d (or exception) at pc %#x", sysno, regs.Pc), false
	}
}
