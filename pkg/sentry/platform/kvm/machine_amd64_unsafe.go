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

//go:build amd64
// +build amd64

package kvm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

func rdfsbase() uint64
func rdgsbase() uint64

// loadSegments copies the current segments.
//
// This may be called from within the signal context and throws on error.
//
//go:nosplit
func (c *vCPU) loadSegments() {
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_SIGALTSTACK, 0, uintptr(unsafe.Pointer(&c.signalStack)), 0); errno != 0 {
		throw("sigaltstack")
	}
	if hasFSGSBASE {
		c.CPU.Registers().Fs_base = rdfsbase()
		c.CPU.Registers().Gs_base = rdgsbase()
	} else {
		if errno := hostsyscall.RawSyscallErrno(
			unix.SYS_ARCH_PRCTL,
			linux.ARCH_GET_FS,
			uintptr(unsafe.Pointer(&c.CPU.Registers().Fs_base)),
			0); errno != 0 {
			throw("getting FS segment")
		}
		if errno := hostsyscall.RawSyscallErrno(
			unix.SYS_ARCH_PRCTL,
			linux.ARCH_GET_GS,
			uintptr(unsafe.Pointer(&c.CPU.Registers().Gs_base)),
			0); errno != 0 {
			throw("getting GS segment")
		}
	}
}

// setCPUID sets the CPUID to be used by the guest.
func (c *vCPU) setCPUID() error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_CPUID2,
		uintptr(unsafe.Pointer(&cpuidSupported))); errno != 0 {
		return fmt.Errorf("error setting CPUID: %v", errno)
	}
	return nil
}

func (c *vCPU) setPAT() error {
	// See Intel SDM Vol. 3, Sec. 13.12.2 "IA32_PAT MSR", or AMD64 APM Vol. 2,
	// Sec. 7.8.1 "PAT Register".
	const (
		_MSR_IA32_PAT = 0x277

		_PAT_UC = 0x00
		_PAT_WC = 0x01
		_PAT_WB = 0x06
	)
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_IA32_PAT
	if hostarch.NumMemoryTypes != 3 {
		panic("additional memory types must be configured in PAT")
	}
	registers.entries[0].data = (_PAT_WB << (hostarch.MemoryTypeWriteBack * 8)) |
		(_PAT_WC << (hostarch.MemoryTypeWriteCombine * 8)) |
		(_PAT_UC << (hostarch.MemoryTypeUncached * 8))
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error setting PAT: %v", errno)
	}
	return nil
}

// getTSCFreq gets the TSC frequency.
//
// If mustSucceed is true, then this function panics on error.
func (c *vCPU) getTSCFreq() (uintptr, error) {
	rawFreq, errno := hostsyscall.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_TSC_KHZ,
		0 /* ignored */)
	if errno != 0 {
		return 0, errno
	}
	return rawFreq, nil
}

// setTSCFreq sets the TSC frequency.
func (c *vCPU) setTSCFreq(freq uintptr) error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_TSC_KHZ,
		freq /* khz */); errno != 0 {
		return fmt.Errorf("error setting TSC frequency: %v", errno)
	}
	return nil
}

// setTSCOffset sets the TSC offset to zero.
func (c *vCPU) setTSCOffset() error {
	offset := uint64(0)
	da := struct {
		flags uint32
		group uint32
		attr  uint64
		addr  unsafe.Pointer
	}{
		group: _KVM_VCPU_TSC_CTRL,
		attr:  _KVM_VCPU_TSC_OFFSET,
		addr:  unsafe.Pointer(&offset),
	}
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_DEVICE_ATTR,
		uintptr(unsafe.Pointer(&da))); errno != 0 {
		return fmt.Errorf("error setting tsc offset: %v", errno)
	}
	return nil
}

// setTSC sets the TSC value.
func (c *vCPU) setTSC(value uint64) error {
	const _MSR_IA32_TSC = 0x00000010
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_IA32_TSC
	registers.entries[0].data = value
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error setting tsc: %v", errno)
	}
	return nil
}

func (c *vCPU) enableCPUIDFaulting() error {
	const (
		_MSR_MISC_FEATURES_ENABLE              = 0x140
		_MSR_MISC_FEATURES_ENABLES_CPUID_FAULT = 1 << 0
	)
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_MISC_FEATURES_ENABLE
	registers.entries[0].data = _MSR_MISC_FEATURES_ENABLES_CPUID_FAULT
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error enabling CPUID faulting: %v", errno)
	}
	return nil
}

// setUserRegisters sets user registers in the vCPU.
//
//go:nosplit
func (c *vCPU) setUserRegisters(uregs *userRegs) unix.Errno {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_REGS,
		uintptr(unsafe.Pointer(uregs))); errno != 0 {
		return errno
	}
	return 0
}

// getUserRegisters reloads user registers in the vCPU.
//
// This is safe to call from a nosplit context.
//
//go:nosplit
func (c *vCPU) getUserRegisters(uregs *userRegs) unix.Errno {
	if errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_REGS,
		uintptr(unsafe.Pointer(uregs))); errno != 0 {
		return errno
	}
	return 0
}

// setSystemRegisters sets system registers.
func (c *vCPU) setSystemRegisters(sregs *systemRegs) error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_SREGS,
		uintptr(unsafe.Pointer(sregs))); errno != 0 {
		return fmt.Errorf("error setting system registers: %v", errno)
	}
	return nil
}

// getSystemRegisters sets system registers.
//
//go:nosplit
func (c *vCPU) getSystemRegisters(sregs *systemRegs) unix.Errno {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_SREGS,
		uintptr(unsafe.Pointer(sregs))); errno != 0 {
		return errno
	}
	return 0
}

//go:nosplit
func seccompMmapSyscall(context unsafe.Pointer) (uintptr, uintptr, unix.Errno) {
	ctx := bluepillArchContext(context)

	// MAP_DENYWRITE is deprecated and ignored by kernel. We use it only for seccomp filters.
	addr, e := hostsyscall.RawSyscall6(uintptr(ctx.Rax), uintptr(ctx.Rdi), uintptr(ctx.Rsi),
		uintptr(ctx.Rdx), uintptr(ctx.R10)|unix.MAP_DENYWRITE, uintptr(ctx.R8), uintptr(ctx.R9))
	if e != 0 {
		ctx.Rax = uint64(-e)
	} else {
		ctx.Rax = uint64(addr)
	}

	return addr, uintptr(ctx.Rsi), unix.Errno(e)
}
