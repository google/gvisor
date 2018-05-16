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

// +build amd64

package kvm

import (
	"fmt"
	"reflect"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// initArchState initializes architecture-specific state.
func (m *machine) initArchState(vCPUs int) error {
	// Set the legacy TSS address. This address is covered by the reserved
	// range (up to 4GB). In fact, this is a main reason it exists.
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(m.fd),
		_KVM_SET_TSS_ADDR,
		uintptr(reservedMemory-(3*usermem.PageSize))); errno != 0 {
		return errno
	}
	return nil
}

// initArchState initializes architecture-specific state.
func (c *vCPU) initArchState() error {
	var (
		kernelSystemRegs systemRegs
		kernelUserRegs   userRegs
	)

	// Set base control registers.
	kernelSystemRegs.CR0 = c.CR0()
	kernelSystemRegs.CR4 = c.CR4()
	kernelSystemRegs.EFER = c.EFER()

	// Set the IDT & GDT in the registers.
	kernelSystemRegs.IDT.base, kernelSystemRegs.IDT.limit = c.IDT()
	kernelSystemRegs.GDT.base, kernelSystemRegs.GDT.limit = c.GDT()
	kernelSystemRegs.CS.Load(&ring0.KernelCodeSegment, ring0.Kcode)
	kernelSystemRegs.DS.Load(&ring0.UserDataSegment, ring0.Udata)
	kernelSystemRegs.ES.Load(&ring0.UserDataSegment, ring0.Udata)
	kernelSystemRegs.SS.Load(&ring0.KernelDataSegment, ring0.Kdata)
	kernelSystemRegs.FS.Load(&ring0.UserDataSegment, ring0.Udata)
	kernelSystemRegs.GS.Load(&ring0.UserDataSegment, ring0.Udata)
	tssBase, tssLimit, tss := c.TSS()
	kernelSystemRegs.TR.Load(tss, ring0.Tss)
	kernelSystemRegs.TR.base = tssBase
	kernelSystemRegs.TR.limit = uint32(tssLimit)

	// Point to kernel page tables.
	kernelSystemRegs.CR3 = c.machine.kernel.PageTables.FlushCR3()

	// Set the CPUID; this is required before setting system registers,
	// since KVM will reject several CR4 bits if the CPUID does not
	// indicate the support is available.
	if err := c.setCPUID(); err != nil {
		return err
	}

	// Set the entrypoint for the kernel.
	kernelUserRegs.RIP = uint64(reflect.ValueOf(ring0.Start).Pointer())
	kernelUserRegs.RAX = uint64(reflect.ValueOf(&c.CPU).Pointer())
	kernelUserRegs.RFLAGS = ring0.KernelFlagsSet

	// Set the system registers.
	if err := c.setSystemRegisters(&kernelSystemRegs); err != nil {
		return err
	}

	// Set the user registers.
	if err := c.setUserRegisters(&kernelUserRegs); err != nil {
		return err
	}

	// Set the time offset to the host native time.
	return c.setSystemTime()
}

// fault generates an appropriate fault return.
//
//go:nosplit
func (c *vCPU) fault(signal int32) (*arch.SignalInfo, usermem.AccessType, error) {
	bluepill(c) // Probably no-op, but may not be.
	faultAddr := ring0.ReadCR2()
	code, user := c.ErrorCode()
	if !user {
		// The last fault serviced by this CPU was not a user
		// fault, so we can't reliably trust the faultAddr or
		// the code provided here. We need to re-execute.
		return nil, usermem.NoAccess, platform.ErrContextInterrupt
	}
	info := &arch.SignalInfo{Signo: signal}
	info.SetAddr(uint64(faultAddr))
	accessType := usermem.AccessType{
		Read:    code&(1<<1) == 0,
		Write:   code&(1<<1) != 0,
		Execute: code&(1<<4) != 0,
	}
	return info, accessType, platform.ErrContextSignal
}

// SwitchToUser unpacks architectural-details.
func (c *vCPU) SwitchToUser(regs *syscall.PtraceRegs, fpState *byte, pt *pagetables.PageTables, flags ring0.Flags) (*arch.SignalInfo, usermem.AccessType, error) {
	// See below.
	var vector ring0.Vector

	// Past this point, stack growth can cause system calls (and a break
	// from guest mode). So we need to ensure that between the bluepill
	// call here and the switch call immediately below, no additional
	// allocations occur.
	entersyscall()
	bluepill(c)
	vector = c.CPU.SwitchToUser(regs, fpState, pt, flags)
	exitsyscall()

	switch vector {
	case ring0.Syscall, ring0.SyscallInt80:
		// Fast path: system call executed.
		return nil, usermem.NoAccess, nil

	case ring0.PageFault:
		return c.fault(int32(syscall.SIGSEGV))

	case ring0.Debug, ring0.Breakpoint:
		info := &arch.SignalInfo{Signo: int32(syscall.SIGTRAP)}
		return info, usermem.AccessType{}, platform.ErrContextSignal

	case ring0.GeneralProtectionFault:
		if !ring0.IsCanonical(regs.Rip) {
			// If the RIP is non-canonical, it's a SEGV.
			info := &arch.SignalInfo{Signo: int32(syscall.SIGSEGV)}
			return info, usermem.AccessType{}, platform.ErrContextSignal
		}
		// Otherwise, we deliver a SIGBUS.
		info := &arch.SignalInfo{Signo: int32(syscall.SIGBUS)}
		return info, usermem.AccessType{}, platform.ErrContextSignal

	case ring0.InvalidOpcode:
		info := &arch.SignalInfo{Signo: int32(syscall.SIGILL)}
		return info, usermem.AccessType{}, platform.ErrContextSignal

	case ring0.X87FloatingPointException:
		info := &arch.SignalInfo{Signo: int32(syscall.SIGFPE)}
		return info, usermem.AccessType{}, platform.ErrContextSignal

	case ring0.Vector(bounce):
		return nil, usermem.NoAccess, platform.ErrContextInterrupt

	case ring0.NMI:
		// An NMI is generated only when a fault is not servicable by
		// KVM itself, so we think some mapping is writeable but it's
		// really not. This could happen, e.g. if some file is
		// truncated (and would generate a SIGBUS) and we map it
		// directly into the instance.
		return c.fault(int32(syscall.SIGBUS))

	default:
		panic(fmt.Sprintf("unexpected vector: 0x%x", vector))
	}
}
