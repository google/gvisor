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

package linux

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// pipe2 implements the actual system call with flags.
func pipe2(t *kernel.Task, addr usermem.Addr, flags uint) (uintptr, error) {
	if flags&^(linux.O_NONBLOCK|linux.O_CLOEXEC) != 0 {
		return 0, syscall.EINVAL
	}
	r, w := pipe.NewConnectedPipe(t, pipe.DefaultPipeSize, usermem.PageSize)

	r.SetFlags(linuxToFlags(flags).Settable())
	defer r.DecRef()

	w.SetFlags(linuxToFlags(flags).Settable())
	defer w.DecRef()

	rfd, err := t.FDMap().NewFDFrom(0, r, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0},
		t.ThreadGroup().Limits())
	if err != nil {
		return 0, err
	}

	wfd, err := t.FDMap().NewFDFrom(0, w, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0},
		t.ThreadGroup().Limits())
	if err != nil {
		t.FDMap().Remove(rfd)
		return 0, err
	}

	if _, err := t.CopyOut(addr, []kdefs.FD{rfd, wfd}); err != nil {
		t.FDMap().Remove(rfd)
		t.FDMap().Remove(wfd)
		return 0, syscall.EFAULT
	}
	return 0, nil
}

// Pipe implements linux syscall pipe(2).
func Pipe(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	n, err := pipe2(t, addr, 0)
	return n, nil, err
}

// Pipe2 implements linux syscall pipe2(2).
func Pipe2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := uint(args[1].Uint())

	n, err := pipe2(t, addr, flags)
	return n, nil, err
}
