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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/fasync"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Mknod implements Linux syscall mknod(2).
func Mknod(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := args[1].ModeT()
	dev := args[2].Uint()
	return 0, nil, mknodat(t, linux.AT_FDCWD, addr, linux.FileMode(mode), dev)
}

// Mknodat implements Linux syscall mknodat(2).
func Mknodat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	addr := args[1].Pointer()
	mode := args[2].ModeT()
	dev := args[3].Uint()
	return 0, nil, mknodat(t, dirfd, addr, linux.FileMode(mode), dev)
}

func mknodat(t *kernel.Task, dirfd int32, addr hostarch.Addr, mode linux.FileMode, dev uint32) error {
	path, err := copyInPath(t, addr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)

	// "Zero file type is equivalent to type S_IFREG." - mknod(2)
	if mode.FileType() == 0 {
		mode |= linux.ModeRegular
	}
	major, minor := linux.DecodeDeviceID(dev)
	return t.Kernel().VFS().MknodAt(t, t.Credentials(), &tpop.pop, &vfs.MknodOptions{
		Mode:     mode &^ linux.FileMode(t.FSContext().Umask()),
		DevMajor: uint32(major),
		DevMinor: minor,
	})
}

// Open implements Linux syscall open(2).
func Open(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Uint()
	mode := args[2].ModeT()
	return openat(t, linux.AT_FDCWD, addr, flags, mode)
}

// Openat implements Linux syscall openat(2).
func Openat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	addr := args[1].Pointer()
	flags := args[2].Uint()
	mode := args[3].ModeT()
	return openat(t, dirfd, addr, flags, mode)
}

// Creat implements Linux syscall creat(2).
func Creat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := args[1].ModeT()
	return openat(t, linux.AT_FDCWD, addr, linux.O_WRONLY|linux.O_CREAT|linux.O_TRUNC, mode)
}

func openat(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr, flags uint32, mode uint) (uintptr, *kernel.SyscallControl, error) {
	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, disallowEmptyPath, shouldFollowFinalSymlink(flags&linux.O_NOFOLLOW == 0))
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	file, err := t.Kernel().VFS().OpenAt(t, t.Credentials(), &tpop.pop, &vfs.OpenOptions{
		Flags: flags | linux.O_LARGEFILE,
		Mode:  linux.FileMode(mode & (0777 | linux.S_ISUID | linux.S_ISGID | linux.S_ISVTX) &^ t.FSContext().Umask()),
	})
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0,
	})
	return uintptr(fd), nil, err
}

// Access implements Linux syscall access(2).
func Access(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := args[1].ModeT()

	return 0, nil, accessAt(t, linux.AT_FDCWD, addr, mode, 0 /* flags */)
}

// Faccessat implements Linux syscall faccessat(2).
func Faccessat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	addr := args[1].Pointer()
	mode := args[2].ModeT()

	return 0, nil, accessAt(t, dirfd, addr, mode, 0 /* flags */)
}

// Faccessat2 implements Linux syscall faccessat2(2).
func Faccessat2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	addr := args[1].Pointer()
	mode := args[2].ModeT()
	flags := args[3].Int()

	return 0, nil, accessAt(t, dirfd, addr, mode, flags)
}

func accessAt(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr, mode uint, flags int32) error {
	const rOK = 4
	const wOK = 2
	const xOK = 1

	// Sanity check the mode.
	if mode&^(rOK|wOK|xOK) != 0 {
		return linuxerr.EINVAL
	}

	// faccessat2(2) isn't documented as supporting AT_EMPTY_PATH, but it does.
	if flags&^(linux.AT_EACCESS|linux.AT_SYMLINK_NOFOLLOW|linux.AT_EMPTY_PATH) != 0 {
		return linuxerr.EINVAL
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, shouldAllowEmptyPath(flags&linux.AT_EMPTY_PATH != 0), shouldFollowFinalSymlink(flags&linux.AT_SYMLINK_NOFOLLOW == 0))
	if err != nil {
		return err
	}
	defer tpop.Release(t)

	creds := t.Credentials()
	if flags&linux.AT_EACCESS == 0 {
		// access(2) and faccessat(2) check permissions using real
		// UID/GID, not effective UID/GID.
		//
		// "access() needs to use the real uid/gid, not the effective
		// uid/gid. We do this by temporarily clearing all FS-related
		// capabilities and switching the fsuid/fsgid around to the
		// real ones." -fs/open.c:faccessat
		creds = creds.Fork()
		creds.EffectiveKUID = creds.RealKUID
		creds.EffectiveKGID = creds.RealKGID
		if creds.EffectiveKUID.In(creds.UserNamespace) == auth.RootUID {
			creds.EffectiveCaps = creds.PermittedCaps
		} else {
			creds.EffectiveCaps = 0
		}
	}

	return t.Kernel().VFS().AccessAt(t, creds, vfs.AccessTypes(mode), &tpop.pop)
}

// Ioctl implements Linux syscall ioctl(2).
func Ioctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if file.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	// Handle ioctls that apply to all FDs.
	switch args[1].Int() {
	case linux.FIONCLEX:
		t.FDTable().SetFlags(t, fd, kernel.FDFlags{
			CloseOnExec: false,
		})
		return 0, nil, nil

	case linux.FIOCLEX:
		t.FDTable().SetFlags(t, fd, kernel.FDFlags{
			CloseOnExec: true,
		})
		return 0, nil, nil

	case linux.FIONBIO:
		var set int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		flags := file.StatusFlags()
		if set != 0 {
			flags |= linux.O_NONBLOCK
		} else {
			flags &^= linux.O_NONBLOCK
		}
		return 0, nil, file.SetStatusFlags(t, t.Credentials(), flags)

	case linux.FIOASYNC:
		var set int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		flags := file.StatusFlags()
		if set != 0 {
			flags |= linux.O_ASYNC
		} else {
			flags &^= linux.O_ASYNC
		}
		file.SetStatusFlags(t, t.Credentials(), flags)
		return 0, nil, nil

	case linux.FIOGETOWN, linux.SIOCGPGRP:
		var who int32
		owner, hasOwner := getAsyncOwner(t, file)
		if hasOwner {
			if owner.Type == linux.F_OWNER_PGRP {
				who = -owner.PID
			} else {
				who = owner.PID
			}
		}
		_, err := primitive.CopyInt32Out(t, args[2].Pointer(), who)
		return 0, nil, err

	case linux.FIOSETOWN, linux.SIOCSPGRP:
		var who int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &who); err != nil {
			return 0, nil, err
		}
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
	}

	ret, err := file.Ioctl(t, t.MemoryManager(), args)
	return ret, nil, err
}

// Getcwd implements Linux syscall getcwd(2).
func Getcwd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	size := args[1].SizeT()

	root := t.FSContext().RootDirectory()
	wd := t.FSContext().WorkingDirectory()
	s, err := t.Kernel().VFS().PathnameForGetcwd(t, root, wd)
	root.DecRef(t)
	wd.DecRef(t)
	if err != nil {
		return 0, nil, err
	}

	// Note this is >= because we need a terminator.
	if uint(len(s)) >= size {
		return 0, nil, linuxerr.ERANGE
	}

	// Construct a byte slice containing a NUL terminator.
	buf := t.CopyScratchBuffer(len(s) + 1)
	copy(buf, s)
	buf[len(buf)-1] = 0

	// Write the pathname slice.
	n, err := t.CopyOutBytes(addr, buf)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// Chdir implements Linux syscall chdir(2).
func Chdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	t.FSContext().SetWorkingDirectory(t, vd)
	vd.DecRef(t)
	return 0, nil, nil
}

// Fchdir implements Linux syscall fchdir(2).
func Fchdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	tpop, err := getTaskPathOperation(t, fd, fspath.Path{}, allowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	t.FSContext().SetWorkingDirectory(t, vd)
	vd.DecRef(t)
	return 0, nil, nil
}

// Chroot implements Linux syscall chroot(2).
func Chroot(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	if !t.HasCapability(linux.CAP_SYS_CHROOT) {
		return 0, nil, linuxerr.EPERM
	}

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	t.FSContext().SetRootDirectory(t, vd)
	vd.DecRef(t)
	return 0, nil, nil
}

// PivotRoot implements Linux syscall pivot_root(2).
func PivotRoot(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr1 := args[0].Pointer()
	addr2 := args[1].Pointer()

	if !t.HasCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}

	newRootPath, err := copyInPath(t, addr1)
	if err != nil {
		return 0, nil, err
	}
	newRootTpop, err := getTaskPathOperation(t, linux.AT_FDCWD, newRootPath, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer newRootTpop.Release(t)
	putOldPath, err := copyInPath(t, addr2)
	if err != nil {
		return 0, nil, err
	}
	putOldTpop, err := getTaskPathOperation(t, linux.AT_FDCWD, putOldPath, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer putOldTpop.Release(t)

	oldRootVd := t.FSContext().RootDirectory()
	defer oldRootVd.DecRef(t)
	newRootVd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &newRootTpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	defer newRootVd.DecRef(t)

	if err := t.Kernel().VFS().PivotRoot(t, t.Credentials(), &newRootTpop.pop, &putOldTpop.pop); err != nil {
		return 0, nil, err
	}
	t.Kernel().ReplaceFSContextRoots(t, oldRootVd, newRootVd)
	return 0, nil, nil
}

// Close implements Linux syscall close(2).
func Close(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	// Note that Remove provides a reference on the file that we may use to
	// flush. It is still active until we drop the final reference below
	// (and other reference-holding operations complete).
	file := t.FDTable().Remove(t, fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	err := file.OnClose(t)
	return 0, nil, HandleIOError(t, false /* partial */, err, linuxerr.EINTR, "close", file)
}

// CloseRange implements linux syscall close_range(2).
func CloseRange(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	first := args[0].Uint()
	last := args[1].Uint()
	flags := args[2].Uint()

	if (first > last) || (last > math.MaxInt32) {
		return 0, nil, linuxerr.EINVAL
	}

	if (flags & ^(linux.CLOSE_RANGE_CLOEXEC | linux.CLOSE_RANGE_UNSHARE)) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	cloexec := flags & linux.CLOSE_RANGE_CLOEXEC
	unshare := flags & linux.CLOSE_RANGE_UNSHARE

	if unshare != 0 {
		// If possible, we don't want to copy FDs to the new unshared table, because those FDs will
		// be promptly closed and no longer used. So in the case where we know the range extends all
		// the way to the end of the FdTable, we can simply copy the FdTable only up to the start of
		// the range that we are closing.
		if cloexec == 0 && int32(last) >= t.FDTable().GetLastFd() {
			t.UnshareFdTable(int32(first))
		} else {
			t.UnshareFdTable(math.MaxInt32)
		}
	}

	if cloexec != 0 {
		flagToApply := kernel.FDFlags{
			CloseOnExec: true,
		}
		t.FDTable().SetFlagsForRange(t.AsyncContext(), int32(first), int32(last), flagToApply)
		return 0, nil, nil
	}

	fdTable := t.FDTable()
	fd := int32(first)
	for {
		fd, file := fdTable.RemoveNextInRange(t, fd, int32(last))
		if file == nil {
			break
		}

		fd++
		// Per the close_range(2) documentation, errors upon closing file descriptors are ignored.
		_ = file.OnClose(t)
		file.DecRef(t)
	}

	return 0, nil, nil
}

// Dup implements Linux syscall dup(2).
func Dup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	newFD, err := t.NewFDFrom(0, file, kernel.FDFlags{})
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
		file := t.GetFile(oldfd)
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

	file := t.GetFile(oldfd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	err := t.NewFDAt(newfd, file, kernel.FDFlags{
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

	file, flags := t.FDTable().Get(fd)
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
		fd, err := t.NewFDFrom(minfd, file, kernel.FDFlags{
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
		err := t.FDTable().SetFlags(t, fd, kernel.FDFlags{
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
		return 0, nil, posixLock(t, args, file, false /* block */)
	case linux.F_SETLKW:
		return 0, nil, posixLock(t, args, file, true /* block */)
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
		a, err := file.SetAsyncHandler(fasync.New(int(fd)))
		if err != nil {
			return 0, nil, err
		}
		async := a.(*fasync.FileAsync)
		return 0, nil, async.SetSignal(linux.Signal(args[2].Int()))
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

	a, err := file.SetAsyncHandler(fasync.New(fd))
	if err != nil {
		return err
	}
	async := a.(*fasync.FileAsync)
	if pid == 0 {
		async.ClearOwner()
		return nil
	}

	switch ownerType {
	case linux.F_OWNER_TID:
		task := t.PIDNamespace().TaskWithID(kernel.ThreadID(pid))
		if task == nil {
			return linuxerr.ESRCH
		}
		async.SetOwnerTask(t, task)
		return nil
	case linux.F_OWNER_PID:
		tg := t.PIDNamespace().ThreadGroupWithID(kernel.ThreadID(pid))
		if tg == nil {
			return linuxerr.ESRCH
		}
		async.SetOwnerThreadGroup(t, tg)
		return nil
	case linux.F_OWNER_PGRP:
		pg := t.PIDNamespace().ProcessGroupWithID(kernel.ProcessGroupID(pid))
		if pg == nil {
			return linuxerr.ESRCH
		}
		async.SetOwnerProcessGroup(t, pg)
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

func posixLock(t *kernel.Task, args arch.SyscallArguments, file *vfs.FileDescription, block bool) error {
	// Copy in the lock request.
	flockAddr := args[2].Pointer()
	var flock linux.Flock
	if _, err := flock.CopyIn(t, flockAddr); err != nil {
		return err
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
		return file.LockPOSIX(t, t.FDTable(), int32(t.TGIDInRoot()), lock.ReadLock, r, block)

	case linux.F_WRLCK:
		if !file.IsWritable() {
			return linuxerr.EBADF
		}
		return file.LockPOSIX(t, t.FDTable(), int32(t.TGIDInRoot()), lock.WriteLock, r, block)

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

	file := t.GetFile(fd)
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

// Mkdir implements Linux syscall mkdir(2).
func Mkdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := args[1].ModeT()
	return 0, nil, mkdirat(t, linux.AT_FDCWD, addr, mode)
}

// Mkdirat implements Linux syscall mkdirat(2).
func Mkdirat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	addr := args[1].Pointer()
	mode := args[2].ModeT()
	return 0, nil, mkdirat(t, dirfd, addr, mode)
}

func mkdirat(t *kernel.Task, dirfd int32, addr hostarch.Addr, mode uint) error {
	path, err := copyInPath(t, addr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)
	return t.Kernel().VFS().MkdirAt(t, t.Credentials(), &tpop.pop, &vfs.MkdirOptions{
		Mode: linux.FileMode(mode & (0777 | linux.S_ISVTX) &^ t.FSContext().Umask()),
	})
}

// Rmdir implements Linux syscall rmdir(2).
func Rmdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	return 0, nil, rmdirat(t, linux.AT_FDCWD, pathAddr)
}

func rmdirat(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr) error {
	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)
	return t.Kernel().VFS().RmdirAt(t, t.Credentials(), &tpop.pop)
}

// Symlink implements Linux syscall symlink(2).
func Symlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	targetAddr := args[0].Pointer()
	linkpathAddr := args[1].Pointer()
	return 0, nil, symlinkat(t, targetAddr, linux.AT_FDCWD, linkpathAddr)
}

// Symlinkat implements Linux syscall symlinkat(2).
func Symlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	targetAddr := args[0].Pointer()
	newdirfd := args[1].Int()
	linkpathAddr := args[2].Pointer()
	return 0, nil, symlinkat(t, targetAddr, newdirfd, linkpathAddr)
}

func symlinkat(t *kernel.Task, targetAddr hostarch.Addr, newdirfd int32, linkpathAddr hostarch.Addr) error {
	target, err := t.CopyInString(targetAddr, linux.PATH_MAX)
	if err != nil {
		return err
	}
	if len(target) == 0 {
		return linuxerr.ENOENT
	}
	linkpath, err := copyInPath(t, linkpathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, newdirfd, linkpath, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)
	return t.Kernel().VFS().SymlinkAt(t, t.Credentials(), &tpop.pop, target)
}

// Link implements Linux syscall link(2).
func Link(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldpathAddr := args[0].Pointer()
	newpathAddr := args[1].Pointer()
	return 0, nil, linkat(t, linux.AT_FDCWD, oldpathAddr, linux.AT_FDCWD, newpathAddr, 0 /* flags */)
}

// Linkat implements Linux syscall linkat(2).
func Linkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	olddirfd := args[0].Int()
	oldpathAddr := args[1].Pointer()
	newdirfd := args[2].Int()
	newpathAddr := args[3].Pointer()
	flags := args[4].Int()
	return 0, nil, linkat(t, olddirfd, oldpathAddr, newdirfd, newpathAddr, flags)
}

func linkat(t *kernel.Task, olddirfd int32, oldpathAddr hostarch.Addr, newdirfd int32, newpathAddr hostarch.Addr, flags int32) error {
	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_FOLLOW) != 0 {
		return linuxerr.EINVAL
	}
	if flags&linux.AT_EMPTY_PATH != 0 && !t.HasCapability(linux.CAP_DAC_READ_SEARCH) {
		return linuxerr.ENOENT
	}

	oldpath, err := copyInPath(t, oldpathAddr)
	if err != nil {
		return err
	}
	oldtpop, err := getTaskPathOperation(t, olddirfd, oldpath, shouldAllowEmptyPath(flags&linux.AT_EMPTY_PATH != 0), shouldFollowFinalSymlink(flags&linux.AT_SYMLINK_FOLLOW != 0))
	if err != nil {
		return err
	}
	defer oldtpop.Release(t)

	newpath, err := copyInPath(t, newpathAddr)
	if err != nil {
		return err
	}
	newtpop, err := getTaskPathOperation(t, newdirfd, newpath, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer newtpop.Release(t)

	return t.Kernel().VFS().LinkAt(t, t.Credentials(), &oldtpop.pop, &newtpop.pop)
}

// Readlinkat implements Linux syscall readlinkat(2).
func Readlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	bufAddr := args[2].Pointer()
	size := args[3].SizeT()
	return readlinkat(t, dirfd, pathAddr, bufAddr, size)
}

// Readlink implements Linux syscall readlink(2).
func Readlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	bufAddr := args[1].Pointer()
	size := args[2].SizeT()
	return readlinkat(t, linux.AT_FDCWD, pathAddr, bufAddr, size)
}

func readlinkat(t *kernel.Task, dirfd int32, pathAddr, bufAddr hostarch.Addr, size uint) (uintptr, *kernel.SyscallControl, error) {
	if int(size) <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}
	// "Since Linux 2.6.39, pathname can be an empty string, in which case the
	// call operates on the symbolic link referred to by dirfd ..." -
	// readlinkat(2)
	tpop, err := getTaskPathOperation(t, dirfd, path, allowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	target, err := t.Kernel().VFS().ReadlinkAt(t, t.Credentials(), &tpop.pop)
	if err != nil {
		return 0, nil, err
	}

	if len(target) > int(size) {
		target = target[:size]
	}
	n, err := t.CopyOutBytes(bufAddr, gohacks.ImmutableBytesFromString(target))
	if n == 0 {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// Unlink implements Linux syscall unlink(2).
func Unlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	return 0, nil, unlinkat(t, linux.AT_FDCWD, pathAddr)
}

func unlinkat(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr) error {
	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)
	return t.Kernel().VFS().UnlinkAt(t, t.Credentials(), &tpop.pop)
}

// Unlinkat implements Linux syscall unlinkat(2).
func Unlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	flags := args[2].Int()

	if flags&^linux.AT_REMOVEDIR != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if flags&linux.AT_REMOVEDIR != 0 {
		return 0, nil, rmdirat(t, dirfd, pathAddr)
	}
	return 0, nil, unlinkat(t, dirfd, pathAddr)
}

func setstatat(t *kernel.Task, dirfd int32, path fspath.Path, shouldAllowEmptyPath shouldAllowEmptyPath, shouldFollowFinalSymlink shouldFollowFinalSymlink, opts *vfs.SetStatOptions) error {
	root := t.FSContext().RootDirectory()
	defer root.DecRef(t)
	start := root
	if !path.Absolute {
		if !path.HasComponents() && !bool(shouldAllowEmptyPath) {
			return linuxerr.ENOENT
		}
		if dirfd == linux.AT_FDCWD {
			start = t.FSContext().WorkingDirectory()
			defer start.DecRef(t)
		} else {
			dirfile := t.GetFile(dirfd)
			if dirfile == nil {
				return linuxerr.EBADF
			}
			if !path.HasComponents() {
				// Use FileDescription.SetStat() instead of
				// VirtualFilesystem.SetStatAt(), since the former may be able
				// to use opened file state to expedite the SetStat.
				err := dirfile.SetStat(t, *opts)
				dirfile.DecRef(t)
				return err
			}
			start = dirfile.VirtualDentry()
			start.IncRef()
			defer start.DecRef(t)
			dirfile.DecRef(t)
		}
	}
	return t.Kernel().VFS().SetStatAt(t, t.Credentials(), &vfs.PathOperation{
		Root:               root,
		Start:              start,
		Path:               path,
		FollowFinalSymlink: bool(shouldFollowFinalSymlink),
	}, opts)
}

func handleSetSizeError(t *kernel.Task, err error) error {
	if err == linuxerr.ErrExceedsFileSizeLimit {
		// Convert error to EFBIG and send a SIGXFSZ per setrlimit(2).
		t.SendSignal(kernel.SignalInfoNoInfo(linux.SIGXFSZ, t, t))
		return linuxerr.EFBIG
	}
	return err
}

// Truncate implements Linux syscall truncate(2).
func Truncate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].Int64()

	if length < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}

	err = setstatat(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink, &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_SIZE,
			Size: uint64(length),
		},
		NeedWritePerm: true,
	})
	return 0, nil, handleSetSizeError(t, err)
}

// Ftruncate implements Linux syscall ftruncate(2).
func Ftruncate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	length := args[1].Int64()

	if length < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if !file.IsWritable() {
		return 0, nil, linuxerr.EINVAL
	}

	err := file.SetStat(t, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_SIZE,
			Size: uint64(length),
		},
	})
	return 0, nil, handleSetSizeError(t, err)
}

// Umask implements linux syscall umask(2).
func Umask(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	mask := args[0].ModeT()
	mask = t.FSContext().SwapUmask(mask & 0777)
	return uintptr(mask), nil, nil
}

// Chown implements Linux syscall chown(2).
func Chown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	owner := args[1].Int()
	group := args[2].Int()
	return 0, nil, fchownat(t, linux.AT_FDCWD, pathAddr, owner, group, 0 /* flags */)
}

// Lchown implements Linux syscall lchown(2).
func Lchown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	owner := args[1].Int()
	group := args[2].Int()
	return 0, nil, fchownat(t, linux.AT_FDCWD, pathAddr, owner, group, linux.AT_SYMLINK_NOFOLLOW)
}

// Fchownat implements Linux syscall fchownat(2).
func Fchownat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	owner := args[2].Int()
	group := args[3].Int()
	flags := args[4].Int()
	return 0, nil, fchownat(t, dirfd, pathAddr, owner, group, flags)
}

func fchownat(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr, owner, group, flags int32) error {
	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW) != 0 {
		return linuxerr.EINVAL
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForChown(t, owner, group, &opts); err != nil {
		return err
	}

	return setstatat(t, dirfd, path, shouldAllowEmptyPath(flags&linux.AT_EMPTY_PATH != 0), shouldFollowFinalSymlink(flags&linux.AT_SYMLINK_NOFOLLOW == 0), &opts)
}

func populateSetStatOptionsForChown(t *kernel.Task, owner, group int32, opts *vfs.SetStatOptions) error {
	userns := t.UserNamespace()
	if owner != -1 {
		kuid := userns.MapToKUID(auth.UID(owner))
		if !kuid.Ok() {
			return linuxerr.EINVAL
		}
		opts.Stat.Mask |= linux.STATX_UID
		opts.Stat.UID = uint32(kuid)
	}
	if group != -1 {
		kgid := userns.MapToKGID(auth.GID(group))
		if !kgid.Ok() {
			return linuxerr.EINVAL
		}
		opts.Stat.Mask |= linux.STATX_GID
		opts.Stat.GID = uint32(kgid)
	}
	return nil
}

// Fchown implements Linux syscall fchown(2).
func Fchown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	owner := args[1].Int()
	group := args[2].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForChown(t, owner, group, &opts); err != nil {
		return 0, nil, err
	}
	return 0, nil, file.SetStat(t, opts)
}

const chmodMask = 0777 | linux.S_ISUID | linux.S_ISGID | linux.S_ISVTX

// Chmod implements Linux syscall chmod(2).
func Chmod(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	mode := args[1].ModeT()
	return 0, nil, fchmodat(t, linux.AT_FDCWD, pathAddr, mode)
}

// Fchmodat implements Linux syscall fchmodat(2).
func Fchmodat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	mode := args[2].ModeT()
	return 0, nil, fchmodat(t, dirfd, pathAddr, mode)
}

func fchmodat(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr, mode uint) error {
	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}

	return setstatat(t, dirfd, path, disallowEmptyPath, followFinalSymlink, &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_MODE,
			Mode: uint16(mode & chmodMask),
		},
	})
}

// Fchmod implements Linux syscall fchmod(2).
func Fchmod(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	mode := args[1].ModeT()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	return 0, nil, file.SetStat(t, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_MODE,
			Mode: uint16(mode & chmodMask),
		},
	})
}

// Utime implements Linux syscall utime(2).
func Utime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	timesAddr := args[1].Pointer()

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}

	opts := vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_ATIME | linux.STATX_MTIME,
		},
	}
	if timesAddr == 0 {
		opts.Stat.Atime.Nsec = linux.UTIME_NOW
		opts.Stat.Mtime.Nsec = linux.UTIME_NOW
	} else {
		var times linux.Utime
		if _, err := times.CopyIn(t, timesAddr); err != nil {
			return 0, nil, err
		}
		opts.Stat.Atime.Sec = times.Actime
		opts.Stat.Mtime.Sec = times.Modtime
	}

	return 0, nil, setstatat(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink, &opts)
}

// Utimes implements Linux syscall utimes(2).
func Utimes(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	timesAddr := args[1].Pointer()

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForUtimes(t, timesAddr, &opts); err != nil {
		return 0, nil, err
	}

	return 0, nil, setstatat(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink, &opts)
}

// Futimesat implements Linux syscall futimesat(2).
func Futimesat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	timesAddr := args[2].Pointer()

	// "If filename is NULL and dfd refers to an open file, then operate on the
	// file. Otherwise look up filename, possibly using dfd as a starting
	// point." - fs/utimes.c
	var path fspath.Path
	shouldAllowEmptyPath := allowEmptyPath
	if dirfd == linux.AT_FDCWD || pathAddr != 0 {
		var err error
		path, err = copyInPath(t, pathAddr)
		if err != nil {
			return 0, nil, err
		}
		shouldAllowEmptyPath = disallowEmptyPath
	}

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForUtimes(t, timesAddr, &opts); err != nil {
		return 0, nil, err
	}

	return 0, nil, setstatat(t, dirfd, path, shouldAllowEmptyPath, followFinalSymlink, &opts)
}

func populateSetStatOptionsForUtimes(t *kernel.Task, timesAddr hostarch.Addr, opts *vfs.SetStatOptions) error {
	if timesAddr == 0 {
		opts.Stat.Mask = linux.STATX_ATIME | linux.STATX_MTIME
		opts.Stat.Atime.Nsec = linux.UTIME_NOW
		opts.Stat.Mtime.Nsec = linux.UTIME_NOW
		return nil
	}
	var times [2]linux.Timeval
	if _, err := linux.CopyTimevalSliceIn(t, timesAddr, times[:]); err != nil {
		return err
	}
	if times[0].Usec < 0 || times[0].Usec > 999999 || times[1].Usec < 0 || times[1].Usec > 999999 {
		return linuxerr.EINVAL
	}
	opts.Stat.Mask = linux.STATX_ATIME | linux.STATX_MTIME
	opts.Stat.Atime = linux.StatxTimestamp{
		Sec:  times[0].Sec,
		Nsec: uint32(times[0].Usec * 1000),
	}
	opts.Stat.Mtime = linux.StatxTimestamp{
		Sec:  times[1].Sec,
		Nsec: uint32(times[1].Usec * 1000),
	}
	return nil
}

// Utimensat implements Linux syscall utimensat(2).
func Utimensat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	timesAddr := args[2].Pointer()
	flags := args[3].Int()

	// Linux requires that the UTIME_OMIT check occur before checking path or
	// flags.
	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForUtimens(t, timesAddr, &opts); err != nil {
		return 0, nil, err
	}
	if opts.Stat.Mask == 0 {
		return 0, nil, nil
	}

	if flags&^linux.AT_SYMLINK_NOFOLLOW != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// "If filename is NULL and dfd refers to an open file, then operate on the
	// file. Otherwise look up filename, possibly using dfd as a starting
	// point." - fs/utimes.c
	var path fspath.Path
	shouldAllowEmptyPath := allowEmptyPath
	if dirfd == linux.AT_FDCWD || pathAddr != 0 {
		var err error
		path, err = copyInPath(t, pathAddr)
		if err != nil {
			return 0, nil, err
		}
		shouldAllowEmptyPath = disallowEmptyPath
	}

	return 0, nil, setstatat(t, dirfd, path, shouldAllowEmptyPath, shouldFollowFinalSymlink(flags&linux.AT_SYMLINK_NOFOLLOW == 0), &opts)
}

func populateSetStatOptionsForUtimens(t *kernel.Task, timesAddr hostarch.Addr, opts *vfs.SetStatOptions) error {
	if timesAddr == 0 {
		opts.Stat.Mask = linux.STATX_ATIME | linux.STATX_MTIME
		opts.Stat.Atime.Nsec = linux.UTIME_NOW
		opts.Stat.Mtime.Nsec = linux.UTIME_NOW
		return nil
	}
	var times [2]linux.Timespec
	if _, err := linux.CopyTimespecSliceIn(t, timesAddr, times[:]); err != nil {
		return err
	}
	if times[0].Nsec != linux.UTIME_OMIT {
		if times[0].Nsec != linux.UTIME_NOW && (times[0].Nsec < 0 || times[0].Nsec > 999999999) {
			return linuxerr.EINVAL
		}
		opts.Stat.Mask |= linux.STATX_ATIME
		opts.Stat.Atime = linux.StatxTimestamp{
			Sec:  times[0].Sec,
			Nsec: uint32(times[0].Nsec),
		}
	}
	if times[1].Nsec != linux.UTIME_OMIT {
		if times[1].Nsec != linux.UTIME_NOW && (times[1].Nsec < 0 || times[1].Nsec > 999999999) {
			return linuxerr.EINVAL
		}
		opts.Stat.Mask |= linux.STATX_MTIME
		opts.Stat.Mtime = linux.StatxTimestamp{
			Sec:  times[1].Sec,
			Nsec: uint32(times[1].Nsec),
		}
	}
	return nil
}

// Rename implements Linux syscall rename(2).
func Rename(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldpathAddr := args[0].Pointer()
	newpathAddr := args[1].Pointer()
	return 0, nil, renameat(t, linux.AT_FDCWD, oldpathAddr, linux.AT_FDCWD, newpathAddr, 0 /* flags */)
}

// Renameat implements Linux syscall renameat(2).
func Renameat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	olddirfd := args[0].Int()
	oldpathAddr := args[1].Pointer()
	newdirfd := args[2].Int()
	newpathAddr := args[3].Pointer()
	return 0, nil, renameat(t, olddirfd, oldpathAddr, newdirfd, newpathAddr, 0 /* flags */)
}

// Renameat2 implements Linux syscall renameat2(2).
func Renameat2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	olddirfd := args[0].Int()
	oldpathAddr := args[1].Pointer()
	newdirfd := args[2].Int()
	newpathAddr := args[3].Pointer()
	flags := args[4].Uint()
	return 0, nil, renameat(t, olddirfd, oldpathAddr, newdirfd, newpathAddr, flags)
}

func renameat(t *kernel.Task, olddirfd int32, oldpathAddr hostarch.Addr, newdirfd int32, newpathAddr hostarch.Addr, flags uint32) error {
	oldpath, err := copyInPath(t, oldpathAddr)
	if err != nil {
		return err
	}
	// "If oldpath refers to a symbolic link, the link is renamed" - rename(2)
	oldtpop, err := getTaskPathOperation(t, olddirfd, oldpath, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer oldtpop.Release(t)

	newpath, err := copyInPath(t, newpathAddr)
	if err != nil {
		return err
	}
	newtpop, err := getTaskPathOperation(t, newdirfd, newpath, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return err
	}
	defer newtpop.Release(t)

	return t.Kernel().VFS().RenameAt(t, t.Credentials(), &oldtpop.pop, &newtpop.pop, &vfs.RenameOptions{
		Flags: flags,
	})
}

// Fallocate implements linux system call fallocate(2).
func Fallocate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	mode := args[1].Uint64()
	offset := args[2].Int64()
	length := args[3].Int64()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if !file.IsWritable() {
		return 0, nil, linuxerr.EBADF
	}
	if mode != 0 {
		return 0, nil, linuxerr.ENOTSUP
	}
	if offset < 0 || length <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	size := offset + length
	if size < 0 {
		return 0, nil, linuxerr.EFBIG
	}
	limit := limits.FromContext(t).Get(limits.FileSize).Cur
	if uint64(size) >= limit {
		t.SendSignal(&linux.SignalInfo{
			Signo: int32(linux.SIGXFSZ),
			Code:  linux.SI_USER,
		})
		return 0, nil, linuxerr.EFBIG
	}

	return 0, nil, file.Allocate(t, mode, uint64(offset), uint64(length))
}

// Flock implements linux syscall flock(2).
func Flock(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	operation := args[1].Int()

	file := t.GetFile(fd)
	if file == nil {
		// flock(2): EBADF fd is not an open file descriptor.
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	nonblocking := operation&linux.LOCK_NB != 0
	operation &^= linux.LOCK_NB

	switch operation {
	case linux.LOCK_EX:
		if err := file.LockBSD(t, int32(t.TGIDInRoot()), lock.WriteLock, !nonblocking /* block */); err != nil {
			return 0, nil, err
		}
	case linux.LOCK_SH:
		if err := file.LockBSD(t, int32(t.TGIDInRoot()), lock.ReadLock, !nonblocking /* block */); err != nil {
			return 0, nil, err
		}
	case linux.LOCK_UN:
		if err := file.UnlockBSD(t); err != nil {
			return 0, nil, err
		}
	default:
		// flock(2): EINVAL operation is invalid.
		return 0, nil, linuxerr.EINVAL
	}

	return 0, nil, nil
}

const (
	memfdPrefix     = "memfd:"
	memfdMaxNameLen = linux.NAME_MAX - len(memfdPrefix)
	memfdAllFlags   = uint32(linux.MFD_CLOEXEC | linux.MFD_ALLOW_SEALING)
)

// MemfdCreate implements the linux syscall memfd_create(2).
func MemfdCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Uint()

	if flags&^memfdAllFlags != 0 {
		// Unknown bits in flags.
		return 0, nil, linuxerr.EINVAL
	}

	allowSeals := flags&linux.MFD_ALLOW_SEALING != 0
	cloExec := flags&linux.MFD_CLOEXEC != 0

	name, err := t.CopyInString(addr, memfdMaxNameLen)
	if err != nil {
		return 0, nil, err
	}

	shmMount := t.Kernel().ShmMount()
	file, err := tmpfs.NewMemfd(t, t.Credentials(), shmMount, allowSeals, memfdPrefix+name)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: cloExec,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}
