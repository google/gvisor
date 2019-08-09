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

package ptrace

import (
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// getRegs gets the general purpose register set.
func (t *thread) getRegs(regs *syscall.PtraceRegs) error {
	iovec := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(regs)),
		Len:  uint64(unsafe.Sizeof(*regs)),
	}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_GETREGSET,
		uintptr(t.tid),
		linux.NT_PRSTATUS,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setRegs sets the general purpose register set.
func (t *thread) setRegs(regs *syscall.PtraceRegs) error {
	iovec := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(regs)),
		Len:  uint64(unsafe.Sizeof(*regs)),
	}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_SETREGSET,
		uintptr(t.tid),
		linux.NT_PRSTATUS,
		uintptr(unsafe.Pointer(&iovec)),
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
func (t *thread) clone() (*thread, error) {
	r, ok := usermem.Addr(stackPointer(&t.initRegs)).RoundUp()
	if !ok {
		return nil, syscall.EINVAL
	}
	rval, err := t.syscallIgnoreInterrupt(
		&t.initRegs,
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
		arch.SyscallArgument{Value: uintptr(unsafe.Pointer(&t.initRegs))})
	if err != nil {
		return nil, err
	}

	return &thread{
		tgid: t.tgid,
		tid:  int32(rval),
		cpu:  ^uint32(0),
	}, nil
}
