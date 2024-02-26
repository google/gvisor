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

package systrap

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// getRegs gets the general purpose register set.
func (t *thread) getRegs(regs *arch.Registers) error {
	iovec := unix.Iovec{
		Base: (*byte)(unsafe.Pointer(regs)),
		Len:  uint64(unsafe.Sizeof(*regs)),
	}
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_GETREGSET,
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
func (t *thread) setRegs(regs *arch.Registers) error {
	iovec := unix.Iovec{
		Base: (*byte)(unsafe.Pointer(regs)),
		Len:  uint64(unsafe.Sizeof(*regs)),
	}
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_SETREGSET,
		uintptr(t.tid),
		linux.NT_PRSTATUS,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// getSignalInfo retrieves information about the signal that caused the stop.
func (t *thread) getSignalInfo(si *linux.SignalInfo) error {
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_GETSIGINFO,
		uintptr(t.tid),
		0,
		uintptr(unsafe.Pointer(si)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// clone creates a new sysmsg thread from this one.
//
// The returned thread will be stopped and available for any system thread to
// call attach on it.
//
// Precondition: the OS thread must be locked and own t.
func (t *thread) clone() (*thread, error) {
	r, ok := hostarch.Addr(stackPointer(&t.initRegs)).RoundUp()
	if !ok {
		return nil, unix.EINVAL
	}
	var flags uintptr
	// Create a sysmsg thread.
	//
	// CLONE_THREAD isn't set, because a stub process has SIGSTOP
	// in its queue. A sysmsg thread will not be traced by ptrace,
	// so it will be stopped immediately if it will share signal
	// queue with its stub process.
	flags = uintptr(
		unix.CLONE_FILES |
			unix.CLONE_FS |
			unix.CLONE_PTRACE |
			unix.CLONE_VM |
			linux.SIGKILL)
	rval, err := t.syscallIgnoreInterrupt(
		&t.initRegs,
		unix.SYS_CLONE,
		arch.SyscallArgument{Value: flags},
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
		tgid: int32(rval),
		tid:  int32(rval),
	}, nil
}

// getEventMessage retrieves a message about the ptrace event that just happened.
func (t *thread) getEventMessage() (uintptr, error) {
	var msg uintptr
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_GETEVENTMSG,
		uintptr(t.tid),
		0,
		uintptr(unsafe.Pointer(&msg)),
		0, 0)
	if errno != 0 {
		return msg, errno
	}
	return msg, nil
}
