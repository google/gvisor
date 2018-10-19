// Copyright 2018 Google LLC
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

// Package syscalls is the interface from the application to the kernel.
// Traditionally, syscalls is the interface that is used by applications to
// request services from the kernel of a operating system. We provide a
// user-mode kernel that needs to handle those requests coming from unmodified
// applications. Therefore, we still use the term "syscalls" to denote this
// interface.
//
// Note that the stubs in this package may merely provide the interface, not
// the actual implementation. It just makes writing syscall stubs
// straightforward.
package syscalls

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/eventchannel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	uspb "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls/unimplemented_syscall_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Error returns a syscall handler that will always give the passed error.
func Error(err error) kernel.SyscallFn {
	return func(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
		return 0, nil, err
	}
}

// ErrorWithEvent gives a syscall function that sends an unimplemented
// syscall event via the event channel and returns the passed error.
func ErrorWithEvent(err error) kernel.SyscallFn {
	return func(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
		UnimplementedEvent(t)
		return 0, nil, err
	}
}

// CapError gives a syscall function that checks for capability c.  If the task
// has the capability, it returns ENOSYS, otherwise EPERM. To unprivileged
// tasks, it will seem like there is an implementation.
func CapError(c linux.Capability) kernel.SyscallFn {
	return func(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
		if !t.HasCapability(c) {
			return 0, nil, syserror.EPERM
		}
		UnimplementedEvent(t)
		return 0, nil, syserror.ENOSYS
	}
}

// UnimplementedEvent emits an UnimplementedSyscall event via the event
// channel.
func UnimplementedEvent(t *kernel.Task) {
	eventchannel.Emit(&uspb.UnimplementedSyscall{
		Tid:       int32(t.ThreadID()),
		Registers: t.Arch().StateData().Proto(),
	})
}
