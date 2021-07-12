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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
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
		return 0, nil, linuxerr.EBADF
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
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	newFD, err := t.NewFDFromVFS2(0, file, kernel.FDFlags{})
	if err != nil {
		return 0, nil, linuxerr.EMFILE
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
			return 0, nil, linuxerr.EBADF
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
		return 0, nil, linuxerr.EINVAL
	}

	return dup3(t, oldfd, newfd, flags)
}

func dup3(t *kernel.Task, oldfd, newfd int32, flags uint32) (uintptr, *kernel.SyscallControl, error) {
	if flags&^linux.O_CLOEXEC != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFileVFS2(oldfd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
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
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if file.StatusFlags()&linux.O_PATH != 0 {
		switch cmd {
		case linux.F_DUPFD, linux.F_DUPFD_CLOEXEC, linux.F_GETFD, linux.F_SETFD, linux.F_GETFL:
			// allowed
		default:
			return 0, nil, linuxerr.EBADF
		}
	}

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
				return 0, nil, linuxerr.EINVAL
			}
			ownerType = linux.F_OWNER_PGRP
			who = -who
		}
		return 0, nil, setAsyncOwner(t, int(fd), file, ownerType, who)
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
		return 0, nil, setAsyncOwner(t, int(fd), file, owner.Type, owner.PID)
	case linux.F_SETPIPE_SZ:
		pipefile, ok := file.Impl().(*pipe.VFSPipeFD)
		if !ok {
			return 0, nil, linuxerr.EBADF
		}
		n, err := pipefile.SetPipeSize(int64(args[2].Int()))
		if err != nil {
			return 0, nil, err
		}
		return uintptr(n), nil, nil
	case linux.F_GETPIPE_SZ:
		pipefile, ok := file.Impl().(*pipe.VFSPipeFD)
		if !ok {
			return 0, nil, linuxerr.EBADF
		}
		return uintptr(pipefile.PipeSize()), nil, nil
	case linux.F_GET_SEALS:
		val, err := tmpfs.GetSeals(file)
		return uintptr(val), nil, err
	case linux.F_ADD_SEALS:
		if !file.IsWritable() {
			return 0, nil, linuxerr.EPERM
		}
		err := tmpfs.AddSeals(file, args[2].Uint())
		return 0, nil, err
	case linux.F_SETLK:
		return 0, nil, posixLock(t, args, file, false /* blocking */)
	case linux.F_SETLKW:
		return 0, nil, posixLock(t, args, file, true /* blocking */)
	case linux.F_GETLK:
		return 0, nil, posixTestLock(t, args, file)
	case linux.F_GETSIG:
		a := file.AsyncHandler()
		if a == nil {
			// Default behavior aka SIGIO.
			return 0, nil, nil
		}
		return uintptr(a.(*fasync.FileAsync).Signal()), nil, nil
	case linux.F_SETSIG:
		a := file.SetAsyncHandler(fasync.NewVFS2(int(fd))).(*fasync.FileAsync)
		return 0, nil, a.SetSignal(linux.Signal(args[2].Int()))
	default:
		// Everything else is not yet supported.
		return 0, nil, linuxerr.EINVAL
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

func setAsyncOwner(t *kernel.Task, fd int, file *vfs.FileDescription, ownerType, pid int32) error {
	switch ownerType {
	case linux.F_OWNER_TID, linux.F_OWNER_PID, linux.F_OWNER_PGRP:
		// Acceptable type.
	default:
		return linuxerr.EINVAL
	}

	a := file.SetAsyncHandler(fasync.NewVFS2(fd)).(*fasync.FileAsync)
	if pid == 0 {
		a.ClearOwner()
		return nil
	}

	switch ownerType {
	case linux.F_OWNER_TID:
		task := t.PIDNamespace().TaskWithID(kernel.ThreadID(pid))
		if task == nil {
			return linuxerr.ESRCH
		}
		a.SetOwnerTask(t, task)
		return nil
	case linux.F_OWNER_PID:
		tg := t.PIDNamespace().ThreadGroupWithID(kernel.ThreadID(pid))
		if tg == nil {
			return linuxerr.ESRCH
		}
		a.SetOwnerThreadGroup(t, tg)
		return nil
	case linux.F_OWNER_PGRP:
		pg := t.PIDNamespace().ProcessGroupWithID(kernel.ProcessGroupID(pid))
		if pg == nil {
			return linuxerr.ESRCH
		}
		a.SetOwnerProcessGroup(t, pg)
		return nil
	default:
		return linuxerr.EINVAL
	}
}

func posixTestLock(t *kernel.Task, args arch.SyscallArguments, file *vfs.FileDescription) error {
	// Copy in the lock request.
	flockAddr := args[2].Pointer()
	var flock linux.Flock
	if _, err := flock.CopyIn(t, flockAddr); err != nil {
		return err
	}
	var typ lock.LockType
	switch flock.Type {
	case linux.F_RDLCK:
		typ = lock.ReadLock
	case linux.F_WRLCK:
		typ = lock.WriteLock
	default:
		return linuxerr.EINVAL
	}
	r, err := file.ComputeLockRange(t, uint64(flock.Start), uint64(flock.Len), flock.Whence)
	if err != nil {
		return err
	}

	newFlock, err := file.TestPOSIX(t, t.FDTable(), typ, r)
	if err != nil {
		return err
	}
	newFlock.PID = translatePID(t.PIDNamespace().Root(), t.PIDNamespace(), newFlock.PID)
	if _, err = newFlock.CopyOut(t, flockAddr); err != nil {
		return err
	}
	return nil
}

// translatePID translates a pid from one namespace to another. Note that this
// may race with task termination/creation, in which case the original task
// corresponding to pid may no longer exist. This is used to implement the
// F_GETLK fcntl, which has the same potential race in Linux as well (i.e.,
// there is no synchronization between retrieving the lock PID and translating
// it). See fs/locks.c:posix_lock_to_flock.
func translatePID(old, new *kernel.PIDNamespace, pid int32) int32 {
	return int32(new.IDOfTask(old.TaskWithID(kernel.ThreadID(pid))))
}

func posixLock(t *kernel.Task, args arch.SyscallArguments, file *vfs.FileDescription, blocking bool) error {
	// Copy in the lock request.
	flockAddr := args[2].Pointer()
	var flock linux.Flock
	if _, err := flock.CopyIn(t, flockAddr); err != nil {
		return err
	}

	var blocker lock.Blocker
	if blocking {
		blocker = t
	}

	r, err := file.ComputeLockRange(t, uint64(flock.Start), uint64(flock.Len), flock.Whence)
	if err != nil {
		return err
	}

	switch flock.Type {
	case linux.F_RDLCK:
		if !file.IsReadable() {
			return linuxerr.EBADF
		}
		return file.LockPOSIX(t, t.FDTable(), int32(t.TGIDInRoot()), lock.ReadLock, r, blocker)

	case linux.F_WRLCK:
		if !file.IsWritable() {
			return linuxerr.EBADF
		}
		return file.LockPOSIX(t, t.FDTable(), int32(t.TGIDInRoot()), lock.WriteLock, r, blocker)

	case linux.F_UNLCK:
		return file.UnlockPOSIX(t, t.FDTable(), r)

	default:
		return linuxerr.EINVAL
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
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if file.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	// If the FD refers to a pipe or FIFO, return error.
	if _, isPipe := file.Impl().(*pipe.VFSPipeFD); isPipe {
		return 0, nil, linuxerr.ESPIPE
	}

	switch advice {
	case linux.POSIX_FADV_NORMAL:
	case linux.POSIX_FADV_RANDOM:
	case linux.POSIX_FADV_SEQUENTIAL:
	case linux.POSIX_FADV_WILLNEED:
	case linux.POSIX_FADV_DONTNEED:
	case linux.POSIX_FADV_NOREUSE:
	default:
		return 0, nil, linuxerr.EINVAL
	}

	// Sure, whatever.
	return 0, nil, nil
}
