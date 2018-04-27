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

package ptrace

import (
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// GETREGSET/SETREGSET register set types.
//
// See include/uapi/linux/elf.h.
const (
	// _NT_PRFPREG is for x86 floating-point state without using xsave.
	_NT_PRFPREG = 0x2

	// _NT_X86_XSTATE is for x86 extended state using xsave.
	_NT_X86_XSTATE = 0x202
)

// fpRegSet returns the GETREGSET/SETREGSET register set type to be used.
func fpRegSet(useXsave bool) uintptr {
	if useXsave {
		return _NT_X86_XSTATE
	}
	return _NT_PRFPREG
}

// getRegs sets the regular register set.
func (t *thread) getRegs(regs *syscall.PtraceRegs) error {
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_GETREGS,
		uintptr(t.tid),
		0,
		uintptr(unsafe.Pointer(regs)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setRegs sets the regular register set.
func (t *thread) setRegs(regs *syscall.PtraceRegs) error {
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_SETREGS,
		uintptr(t.tid),
		0,
		uintptr(unsafe.Pointer(regs)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// getFPRegs gets the floating-point data via the GETREGSET ptrace syscall.
func (t *thread) getFPRegs(fpState *arch.FloatingPointData, fpLen uint64, useXsave bool) error {
	iovec := syscall.Iovec{
		Base: (*byte)(fpState),
		Len:  fpLen,
	}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_GETREGSET,
		uintptr(t.tid),
		fpRegSet(useXsave),
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setFPRegs sets the floating-point data via the SETREGSET ptrace syscall.
func (t *thread) setFPRegs(fpState *arch.FloatingPointData, fpLen uint64, useXsave bool) error {
	iovec := syscall.Iovec{
		Base: (*byte)(fpState),
		Len:  fpLen,
	}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_SETREGSET,
		uintptr(t.tid),
		fpRegSet(useXsave),
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// getSignalInfo retrieves information about the signal that caused the stop.
func (t *thread) getSignalInfo(si *arch.SignalInfo) error {
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_GETSIGINFO,
		uintptr(t.tid),
		0,
		uintptr(unsafe.Pointer(si)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// clone creates a new thread from this one.
//
// The returned thread will be stopped and available for any system thread to
// call attach on it.
//
// Precondition: the OS thread must be locked and own t.
func (t *thread) clone(initRegs *syscall.PtraceRegs) (*thread, error) {
	r, ok := usermem.Addr(initRegs.Rsp).RoundUp()
	if !ok {
		return nil, syscall.EINVAL
	}
	rval, err := t.syscallIgnoreInterrupt(
		initRegs,
		syscall.SYS_CLONE,
		arch.SyscallArgument{Value: uintptr(
			syscall.CLONE_FILES |
				syscall.CLONE_FS |
				syscall.CLONE_SIGHAND |
				syscall.CLONE_THREAD |
				syscall.CLONE_PTRACE |
				syscall.CLONE_VM)},
		// The stack pointer is just made up, but we have it be
		// something sensible so the kernel doesn't think we're
		// up to no good. Which we are.
		arch.SyscallArgument{Value: uintptr(r)},
		arch.SyscallArgument{},
		arch.SyscallArgument{},
		// We use these registers initially, but really they
		// could be anything. We're going to stop immediately.
		arch.SyscallArgument{Value: uintptr(unsafe.Pointer(initRegs))})
	if err != nil {
		return nil, err
	}

	return &thread{
		tgid: t.tgid,
		tid:  int32(rval),
		cpu:  ^uint32(0),
	}, nil
}
