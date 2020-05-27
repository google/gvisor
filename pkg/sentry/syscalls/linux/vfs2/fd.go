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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Close implements Linux syscall close(2).
func Close(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	// Note that Remove provides a reference on the file that we may use to
	// flush. It is still active until we drop the final reference below
	// (and other reference-holding operations complete).
	_, file := t.FDTable().Remove(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	err := file.OnClose(t)
	return 0, nil, slinux.HandleIOErrorVFS2(t, false /* partial */, err, syserror.EINTR, "close", file)
}

// Dup implements Linux syscall dup(2).
func Dup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	newFD, err := t.NewFDFromVFS2(0, file, kernel.FDFlags{})
	if err != nil {
		return 0, nil, syserror.EMFILE
	}
	return uintptr(newFD), nil, nil
}

// Dup2 implements Linux syscall dup2(2).
func Dup2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldfd := args[0].Int()
	newfd := args[1].Int()

	if oldfd == newfd {
		// As long as oldfd is valid, dup2() does nothing and returns newfd.
		file := t.GetFileVFS2(oldfd)
		if file == nil {
			return 0, nil, syserror.EBADF
		}
		file.DecRef()
		return uintptr(newfd), nil, nil
	}

	return dup3(t, oldfd, newfd, 0)
}

// Dup3 implements Linux syscall dup3(2).
func Dup3(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldfd := args[0].Int()
	newfd := args[1].Int()
	flags := args[2].Uint()

	if oldfd == newfd {
		return 0, nil, syserror.EINVAL
	}

	return dup3(t, oldfd, newfd, flags)
}

func dup3(t *kernel.Task, oldfd, newfd int32, flags uint32) (uintptr, *kernel.SyscallControl, error) {
	if flags&^linux.O_CLOEXEC != 0 {
		return 0, nil, syserror.EINVAL
	}

	file := t.GetFileVFS2(oldfd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	err := t.NewFDAtVFS2(newfd, file, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(newfd), nil, nil
}

// Fcntl implements linux syscall fcntl(2).
func Fcntl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	cmd := args[1].Int()

	file, flags := t.FDTable().GetVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	switch cmd {
	case linux.F_DUPFD, linux.F_DUPFD_CLOEXEC:
		minfd := args[2].Int()
		fd, err := t.NewFDFromVFS2(minfd, file, kernel.FDFlags{
			CloseOnExec: cmd == linux.F_DUPFD_CLOEXEC,
		})
		if err != nil {
			return 0, nil, err
		}
		return uintptr(fd), nil, nil
	case linux.F_GETFD:
		return uintptr(flags.ToLinuxFDFlags()), nil, nil
	case linux.F_SETFD:
		flags := args[2].Uint()
		t.FDTable().SetFlags(fd, kernel.FDFlags{
			CloseOnExec: flags&linux.FD_CLOEXEC != 0,
		})
		return 0, nil, nil
	case linux.F_GETFL:
		return uintptr(file.StatusFlags()), nil, nil
	case linux.F_SETFL:
		return 0, nil, file.SetStatusFlags(t, t.Credentials(), args[2].Uint())
	case linux.F_SETPIPE_SZ:
		pipefile, ok := file.Impl().(*pipe.VFSPipeFD)
		if !ok {
			return 0, nil, syserror.EBADF
		}
		n, err := pipefile.SetPipeSize(int64(args[2].Int()))
		if err != nil {
			return 0, nil, err
		}
		return uintptr(n), nil, nil
	case linux.F_GETPIPE_SZ:
		pipefile, ok := file.Impl().(*pipe.VFSPipeFD)
		if !ok {
			return 0, nil, syserror.EBADF
		}
		return uintptr(pipefile.PipeSize()), nil, nil
	case linux.F_GET_SEALS:
		val, err := tmpfs.GetSeals(file)
		return uintptr(val), nil, err
	case linux.F_ADD_SEALS:
		if !file.IsWritable() {
			return 0, nil, syserror.EPERM
		}
		err := tmpfs.AddSeals(file, args[2].Uint())
		return 0, nil, err
	default:
		// TODO(gvisor.dev/issue/1623): Everything else is not yet supported.
		return 0, nil, syserror.EINVAL
	}
}
