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
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/fasync"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Close implements Linux syscall close(2).
func Close(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	// Note that Remove provides a reference on the file that we may use to
	// flush. It is still active until we drop the final reference below
	// (and other reference-holding operations complete).
	_, file := t.FDTable().Remove(t, fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

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
	defer file.DecRef(t)

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
		file.DecRef(t)
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
	defer file.DecRef(t)

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
	defer file.DecRef(t)

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
		err := t.FDTable().SetFlagsVFS2(t, fd, kernel.FDFlags{
			CloseOnExec: flags&linux.FD_CLOEXEC != 0,
		})
		return 0, nil, err
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
	case linux.F_GETOWN:
		owner, hasOwner := getAsyncOwner(t, file)
		if !hasOwner {
			return 0, nil, nil
		}
		if owner.Type == linux.F_OWNER_PGRP {
			return uintptr(-owner.PID), nil, nil
		}
		return uintptr(owner.PID), nil, nil
	case linux.F_SETOWN:
		who := args[2].Int()
		ownerType := int32(linux.F_OWNER_PID)
		if who < 0 {
			// Check for overflow before flipping the sign.
			if who-1 > who {
				return 0, nil, syserror.EINVAL
			}
			ownerType = linux.F_OWNER_PGRP
			who = -who
		}
		return 0, nil, setAsyncOwner(t, file, ownerType, who)
	case linux.F_GETOWN_EX:
		owner, hasOwner := getAsyncOwner(t, file)
		if !hasOwner {
			return 0, nil, nil
		}
		_, err := owner.CopyOut(t, args[2].Pointer())
		return 0, nil, err
	case linux.F_SETOWN_EX:
		var owner linux.FOwnerEx
		_, err := owner.CopyIn(t, args[2].Pointer())
		if err != nil {
			return 0, nil, err
		}
		return 0, nil, setAsyncOwner(t, file, owner.Type, owner.PID)
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
	case linux.F_SETLK, linux.F_SETLKW:
		return 0, nil, posixLock(t, args, file, cmd)
	default:
		// Everything else is not yet supported.
		return 0, nil, syserror.EINVAL
	}
}

func getAsyncOwner(t *kernel.Task, fd *vfs.FileDescription) (ownerEx linux.FOwnerEx, hasOwner bool) {
	a := fd.AsyncHandler()
	if a == nil {
		return linux.FOwnerEx{}, false
	}

	ot, otg, opg := a.(*fasync.FileAsync).Owner()
	switch {
	case ot != nil:
		return linux.FOwnerEx{
			Type: linux.F_OWNER_TID,
			PID:  int32(t.PIDNamespace().IDOfTask(ot)),
		}, true
	case otg != nil:
		return linux.FOwnerEx{
			Type: linux.F_OWNER_PID,
			PID:  int32(t.PIDNamespace().IDOfThreadGroup(otg)),
		}, true
	case opg != nil:
		return linux.FOwnerEx{
			Type: linux.F_OWNER_PGRP,
			PID:  int32(t.PIDNamespace().IDOfProcessGroup(opg)),
		}, true
	default:
		return linux.FOwnerEx{}, true
	}
}

func setAsyncOwner(t *kernel.Task, fd *vfs.FileDescription, ownerType, pid int32) error {
	switch ownerType {
	case linux.F_OWNER_TID, linux.F_OWNER_PID, linux.F_OWNER_PGRP:
		// Acceptable type.
	default:
		return syserror.EINVAL
	}

	a := fd.SetAsyncHandler(fasync.NewVFS2).(*fasync.FileAsync)
	if pid == 0 {
		a.ClearOwner()
		return nil
	}

	switch ownerType {
	case linux.F_OWNER_TID:
		task := t.PIDNamespace().TaskWithID(kernel.ThreadID(pid))
		if task == nil {
			return syserror.ESRCH
		}
		a.SetOwnerTask(t, task)
		return nil
	case linux.F_OWNER_PID:
		tg := t.PIDNamespace().ThreadGroupWithID(kernel.ThreadID(pid))
		if tg == nil {
			return syserror.ESRCH
		}
		a.SetOwnerThreadGroup(t, tg)
		return nil
	case linux.F_OWNER_PGRP:
		pg := t.PIDNamespace().ProcessGroupWithID(kernel.ProcessGroupID(pid))
		if pg == nil {
			return syserror.ESRCH
		}
		a.SetOwnerProcessGroup(t, pg)
		return nil
	default:
		return syserror.EINVAL
	}
}

func posixLock(t *kernel.Task, args arch.SyscallArguments, file *vfs.FileDescription, cmd int32) error {
	// Copy in the lock request.
	flockAddr := args[2].Pointer()
	var flock linux.Flock
	if _, err := flock.CopyIn(t, flockAddr); err != nil {
		return err
	}

	var blocker lock.Blocker
	if cmd == linux.F_SETLKW {
		blocker = t
	}

	switch flock.Type {
	case linux.F_RDLCK:
		if !file.IsReadable() {
			return syserror.EBADF
		}
		return file.LockPOSIX(t, t.FDTable(), lock.ReadLock, uint64(flock.Start), uint64(flock.Len), flock.Whence, blocker)

	case linux.F_WRLCK:
		if !file.IsWritable() {
			return syserror.EBADF
		}
		return file.LockPOSIX(t, t.FDTable(), lock.WriteLock, uint64(flock.Start), uint64(flock.Len), flock.Whence, blocker)

	case linux.F_UNLCK:
		return file.UnlockPOSIX(t, t.FDTable(), uint64(flock.Start), uint64(flock.Len), flock.Whence)

	default:
		return syserror.EINVAL
	}
}

// Fadvise64 implements fadvise64(2).
// This implementation currently ignores the provided advice.
func Fadvise64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	length := args[2].Int64()
	advice := args[3].Int()

	// Note: offset is allowed to be negative.
	if length < 0 {
		return 0, nil, syserror.EINVAL
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	// If the FD refers to a pipe or FIFO, return error.
	if _, isPipe := file.Impl().(*pipe.VFSPipeFD); isPipe {
		return 0, nil, syserror.ESPIPE
	}

	switch advice {
	case linux.POSIX_FADV_NORMAL:
	case linux.POSIX_FADV_RANDOM:
	case linux.POSIX_FADV_SEQUENTIAL:
	case linux.POSIX_FADV_WILLNEED:
	case linux.POSIX_FADV_DONTNEED:
	case linux.POSIX_FADV_NOREUSE:
	default:
		return 0, nil, syserror.EINVAL
	}

	// Sure, whatever.
	return 0, nil, nil
}
