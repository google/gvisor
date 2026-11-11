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
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/memutil"
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

func getVCPUEvents(t *testing.T, c *vCPU) kvmVcpuEvents {
	t.Helper()
	var events kvmVcpuEvents
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_VCPU_EVENTS,
		uintptr(unsafe.Pointer(&events))); errno != 0 {
		t.Fatalf("KVM_GET_VCPU_EVENTS failed: %v", errno)
	}
	return events
}

func setVCPUEvents(t *testing.T, c *vCPU, events *kvmVcpuEvents) {
	t.Helper()
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_VCPU_EVENTS,
		uintptr(unsafe.Pointer(events))); errno != 0 {
		t.Fatalf("KVM_SET_VCPU_EVENTS failed: %v", errno)
	}
}

func TestKVMVcpuEvents(t *testing.T) {
	wantSize := uintptr((KVM_GET_VCPU_EVENTS >> 16) & 0x3fff)
	if gotSize := unsafe.Sizeof(kvmVcpuEvents{}); gotSize != wantSize {
		t.Fatalf("sizeof(kvmVcpuEvents) = %d, want %d", gotSize, wantSize)
	}
	bluepillTest(t, func(c *vCPU) {
		redpill()

		events := getVCPUEvents(t, c)
		events.interrupt.shadow = 1
		events.flags |= _KVM_VCPUEVENT_VALID_SHADOW
		setVCPUEvents(t, c, &events)

		// Intel VMX reports 1 (MOV SS); AMD SVM tracks a single
		// interrupt-shadow bit and reports 3 (MOV SS | STI).
		if got := getVCPUEvents(t, c).interrupt.shadow; got&1 == 0 {
			t.Fatalf("interrupt.shadow = %d, want bit 0 set", got)
		}

		events = getVCPUEvents(t, c)
		events.interrupt.shadow = 0
		events.flags |= _KVM_VCPUEVENT_VALID_SHADOW
		setVCPUEvents(t, c, &events)

		if got := getVCPUEvents(t, c).interrupt.shadow; got != 0 {
			t.Fatalf("interrupt.shadow = %d, want 0", got)
		}
	})
}

// TestSigbusInMovSSShadow verifies that an access to unbacked memory made by
// the instruction right after MOV SS (i.e. inside its interrupt shadow)
// produces SIGBUS at that instruction.
func TestSigbusInMovSSShadow(t *testing.T) {
	memfd, err := memutil.CreateMemFD("kvm_movss_sigbus", 0)
	if err != nil {
		t.Fatalf("CreateMemFD failed: %v", err)
	}
	memfile := os.NewFile(uintptr(memfd), "kvm_movss_sigbus")
	defer memfile.Close()

	// Map two pages over a one-page file: the second page is unbacked and
	// any access to it raises SIGBUS.
	const pageSize = uintptr(hostarch.PageSize)
	const mapLen = 2 * pageSize
	if err := memfile.Truncate(int64(pageSize)); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}

	// movl $0x2b, %eax; movl %eax, %ss
	movSS := []byte{0xb8, 0x2b, 0x00, 0x00, 0x00, 0x8e, 0xd0}

	for _, tc := range []struct {
		name string
		// code is placed in the first page at codeOff.
		code    func(pageSize uintptr) (code []byte, codeOff uintptr)
		setRegs func(regs *arch.Registers, addr uintptr)
		// wantRIP is the expected RIP offset from addr.
		wantRIP func(pageSize uintptr) uintptr
	}{
		{
			// The load from the unbacked page is the instruction in the
			// MOV SS shadow.
			name: "DataLoad",
			code: func(uintptr) ([]byte, uintptr) {
				// movq (%rdi), %rbx; syscall
				return append(append([]byte{}, movSS...), 0x48, 0x8b, 0x1f, 0x0f, 0x05), 0
			},
			setRegs: func(regs *arch.Registers, addr uintptr) {
				regs.Rdi = uint64(addr + pageSize)
			},
			wantRIP: func(uintptr) uintptr { return uintptr(len(movSS)) },
		},
		{
			// MOV SS is the last instruction in the first page, so the
			// fetch of the next instruction from the unbacked page
			// happens in the MOV SS shadow.
			name: "InstructionFetch",
			code: func(pageSize uintptr) ([]byte, uintptr) {
				return movSS, pageSize - uintptr(len(movSS))
			},
			setRegs: func(*arch.Registers, uintptr) {},
			wantRIP: func(pageSize uintptr) uintptr { return pageSize },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applicationTest(t, true, testutil.AddrOfSyscallLoop(), func(c *vCPU, regs *arch.Registers, pt *pagetables.PageTables) bool {
				addr, _, errno := unix.RawSyscall6(
					unix.SYS_MMAP,
					0,
					mapLen,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_SHARED|unix.MAP_FILE,
					memfile.Fd(),
					0)
				if errno != 0 {
					t.Fatalf("mmap failed: %v", errno)
				}
				defer unix.RawSyscall(unix.SYS_MUNMAP, addr, mapLen, 0)

				code, codeOff := tc.code(pageSize)
				copy(unsafe.Slice((*byte)(unsafe.Pointer(addr+codeOff)), len(code)), code)

				for {
					testutil.SetTestRegs(regs)
					regs.Rip = uint64(addr + codeOff)
					tc.setRegs(regs, addr)

					var si linux.SignalInfo
					_, err := c.SwitchToUser(ring0.SwitchOpts{
						Registers:          regs,
						FloatingPointState: &dummyFPState,
						PageTables:         pt,
						FullRestore:        true,
					}, &si)
					if err == platform.ErrContextInterrupt {
						continue // Retry.
					}
					if err != platform.ErrContextSignal || si.Signo != int32(unix.SIGBUS) {
						t.Fatalf("SwitchToUser got (%v, signo=%d), want (%v, SIGBUS)", err, si.Signo, platform.ErrContextSignal)
					}
					break
				}
				if want := uint64(addr + tc.wantRIP(pageSize)); regs.Rip != want {
					t.Errorf("regs.Rip = %#x, want %#x", regs.Rip, want)
				}
				return false
			})
		})
	}
}
