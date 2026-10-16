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

//go:build amd64
// +build amd64

package kvm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm/testutil"
)

func TestGetCS(t *testing.T) {
	cs := getcs()
	if cs != 0x33 {
		t.Fatalf("cs = 0x%x", cs)
	}
}

func TestSegments(t *testing.T) {
	applicationTest(t, true, testutil.AddrOfTwiddleSegments(), func(c *vCPU, regs *arch.Registers, pt *pagetables.PageTables) bool {
		testutil.SetTestSegments(regs)
		for {
			var si linux.SignalInfo
			if _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: &dummyFPState,
				PageTables:         pt,
				FullRestore:        true,
			}, &si); err == platform.ErrContextInterrupt {
				continue // Retry.
			} else if err != nil {
				t.Errorf("application segment check with full restore got unexpected error: %v", err)
			}
			if err := testutil.CheckTestSegments(regs); err != nil {
				t.Errorf("application segment check with full restore failed: %v", err)
			}
			break // Done.
		}
		return false
	})
}

func vmcall(ax uintptr) uintptr
func vmmcall(ax uintptr) uintptr

func BenchmarkVMCall(b *testing.B) {
	vmcallIsSupported := cpuid.HostFeatureSet().Intel()
	kvmTest(b, nil, func(c *vCPU) bool {
		for i := 0; i < b.N; i++ {
			bluepill(c)
			if vmcallIsSupported {
				vmcall(0)
			} else {
				vmmcall(0)
			}
		}
		return false
	})
}

// stmxcsr reads the MXCSR control and status register.
func stmxcsr(addr *uint32)

func TestMXCSR(t *testing.T) {
	applicationTest(t, true, testutil.AddrOfSyscallLoop(), func(c *vCPU, regs *arch.Registers, pt *pagetables.PageTables) bool {
		var si linux.SignalInfo
		switchOpts := ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: &dummyFPState,
			PageTables:         pt,
			FullRestore:        true,
		}

		const mxcsrControllMask = uint32(0x1f80)
		mxcsrBefore := uint32(0)
		mxcsrAfter := uint32(0)
		stmxcsr(&mxcsrBefore)
		if mxcsrBefore == 0 {
			// goruntime sets mxcsr to 0x1f80 and it never changes
			// the control configuration.
			panic("mxcsr is zero")
		}
		switchOpts.FloatingPointState.SetMXCSR(0)
		if _, err := c.SwitchToUser(
			switchOpts, &si); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != nil {
			t.Errorf("application syscall failed: %v", err)
		}
		stmxcsr(&mxcsrAfter)
		if mxcsrAfter&mxcsrControllMask != mxcsrBefore&mxcsrControllMask {
			t.Errorf("mxcsr = %x (expected %x)", mxcsrBefore, mxcsrAfter)
		}
		return false
	})
}

//go:nosplit
func nestedVirtIsOn(c *vCPU, fs *cpuid.FeatureSet) bool {
	bluepill(c)
	return fs.HasFeature(cpuid.X86FeatureVMX) || fs.HasFeature(cpuid.X86FeatureSVM)

}

func TestKernelCPUID(t *testing.T) {
	bluepillTest(t, func(c *vCPU) {
		fs := cpuid.FeatureSet{
			Function: &cpuid.Native{},
		}
		if nestedVirtIsOn(c, &fs) {
			t.Fatalf("Nested virtualization is enabled")
		}
	})
}

// disallowedVDSOExit returns a description of the last guest exit of c and
// whether it indicates that a vDSO time call did not run entirely in guest
// mode: an exception, or a system call that reads the time.
//
// A guest kernel system call sets the vector to ^0 and saves the system call
// number in Orig_rax; an exception saves its vector instead.
func disallowedVDSOExit(c *vCPU) (string, bool) {
	regs := c.CPU.Registers()
	if vector := c.CPU.Vector(); vector != ^uintptr(0) {
		return fmt.Sprintf("exception %d at rip %#x, fault address %#x", vector, regs.Rip, c.CPU.FaultAddr()), true
	}
	switch sysno := regs.Orig_rax; sysno {
	case unix.SYS_CLOCK_GETTIME, unix.SYS_GETTIMEOFDAY, unix.SYS_TIME:
		return fmt.Sprintf("time system call %d at rip %#x", sysno, regs.Rip), true
	default:
		return fmt.Sprintf("system call %d at rip %#x", sysno, regs.Rip), false
	}
}
