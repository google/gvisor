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
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
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

	fds, err := t.NewFDs(0, []*fs.File{r, w}, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0,
	})
	if err != nil {
		return 0, err
	}

	if _, err := t.CopyOut(addr, fds); err != nil {
		// The files are not closed in this case, the exact semantics
		// of this error case are not well defined, but they could have
		// already been observed by user space.
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
