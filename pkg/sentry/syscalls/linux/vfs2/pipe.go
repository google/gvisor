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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/pipefs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Pipe implements Linux syscall pipe(2).
func Pipe(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	return 0, nil, pipe2(t, addr, 0)
}

// Pipe2 implements Linux syscall pipe2(2).
func Pipe2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Int()
	return 0, nil, pipe2(t, addr, flags)
}

func pipe2(t *kernel.Task, addr usermem.Addr, flags int32) error {
	if flags&^(linux.O_NONBLOCK|linux.O_CLOEXEC) != 0 {
		return syserror.EINVAL
	}
	r, w := pipefs.NewConnectedPipeFDs(t, t.Kernel().PipeMount(), uint32(flags&linux.O_NONBLOCK))
	defer r.DecRef(t)
	defer w.DecRef(t)

	fds, err := t.NewFDsVFS2(0, []*vfs.FileDescription{r, w}, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0,
	})
	if err != nil {
		return err
	}
	if _, err := t.CopyOut(addr, fds); err != nil {
		for _, fd := range fds {
			if _, file := t.FDTable().Remove(fd); file != nil {
				file.DecRef(t)
			}
		}
		return err
	}
	return nil
}
