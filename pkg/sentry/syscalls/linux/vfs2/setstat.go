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
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

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

func fchmodat(t *kernel.Task, dirfd int32, pathAddr usermem.Addr, mode uint) error {
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

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, file.SetStat(t, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_MODE,
			Mode: uint16(mode & chmodMask),
		},
	})
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

func fchownat(t *kernel.Task, dirfd int32, pathAddr usermem.Addr, owner, group, flags int32) error {
	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW) != 0 {
		return syserror.EINVAL
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
			return syserror.EINVAL
		}
		opts.Stat.Mask |= linux.STATX_UID
		opts.Stat.UID = uint32(kuid)
	}
	if group != -1 {
		kgid := userns.MapToKGID(auth.GID(group))
		if !kgid.Ok() {
			return syserror.EINVAL
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

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForChown(t, owner, group, &opts); err != nil {
		return 0, nil, err
	}
	return 0, nil, file.SetStat(t, opts)
}

// Truncate implements Linux syscall truncate(2).
func Truncate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].Int64()

	if length < 0 {
		return 0, nil, syserror.EINVAL
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
	})
	return 0, nil, handleSetSizeError(t, err)
}

// Ftruncate implements Linux syscall ftruncate(2).
func Ftruncate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	length := args[1].Int64()

	if length < 0 {
		return 0, nil, syserror.EINVAL
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	err := file.SetStat(t, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_SIZE,
			Size: uint64(length),
		},
	})
	return 0, nil, handleSetSizeError(t, err)
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

	opts := vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_ATIME | linux.STATX_MTIME,
		},
	}
	if timesAddr == 0 {
		opts.Stat.Atime.Nsec = linux.UTIME_NOW
		opts.Stat.Mtime.Nsec = linux.UTIME_NOW
	} else {
		var times [2]linux.Timeval
		if _, err := t.CopyIn(timesAddr, &times); err != nil {
			return 0, nil, err
		}
		opts.Stat.Atime = linux.StatxTimestamp{
			Sec:  times[0].Sec,
			Nsec: uint32(times[0].Usec * 1000),
		}
		opts.Stat.Mtime = linux.StatxTimestamp{
			Sec:  times[1].Sec,
			Nsec: uint32(times[1].Usec * 1000),
		}
	}

	return 0, nil, setstatat(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink, &opts)
}

// Utimensat implements Linux syscall utimensat(2).
func Utimensat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	timesAddr := args[2].Pointer()
	flags := args[3].Int()

	if flags&^linux.AT_SYMLINK_NOFOLLOW != 0 {
		return 0, nil, syserror.EINVAL
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForUtimens(t, timesAddr, &opts); err != nil {
		return 0, nil, err
	}

	return 0, nil, setstatat(t, dirfd, path, disallowEmptyPath, followFinalSymlink, &opts)
}

// Futimens implements Linux syscall futimens(2).
func Futimens(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	timesAddr := args[1].Pointer()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	var opts vfs.SetStatOptions
	if err := populateSetStatOptionsForUtimens(t, timesAddr, &opts); err != nil {
		return 0, nil, err
	}

	return 0, nil, file.SetStat(t, opts)
}

func populateSetStatOptionsForUtimens(t *kernel.Task, timesAddr usermem.Addr, opts *vfs.SetStatOptions) error {
	if timesAddr == 0 {
		opts.Stat.Mask = linux.STATX_ATIME | linux.STATX_MTIME
		opts.Stat.Atime.Nsec = linux.UTIME_NOW
		opts.Stat.Mtime.Nsec = linux.UTIME_NOW
		return nil
	}
	var times [2]linux.Timespec
	if _, err := t.CopyIn(timesAddr, &times); err != nil {
		return err
	}
	if times[0].Nsec != linux.UTIME_OMIT {
		opts.Stat.Mask |= linux.STATX_ATIME
		opts.Stat.Atime = linux.StatxTimestamp{
			Sec:  times[0].Sec,
			Nsec: uint32(times[0].Nsec),
		}
	}
	if times[1].Nsec != linux.UTIME_OMIT {
		opts.Stat.Mask |= linux.STATX_MTIME
		opts.Stat.Mtime = linux.StatxTimestamp{
			Sec:  times[1].Sec,
			Nsec: uint32(times[1].Nsec),
		}
	}
	return nil
}

func setstatat(t *kernel.Task, dirfd int32, path fspath.Path, shouldAllowEmptyPath shouldAllowEmptyPath, shouldFollowFinalSymlink shouldFollowFinalSymlink, opts *vfs.SetStatOptions) error {
	root := t.FSContext().RootDirectoryVFS2()
	defer root.DecRef()
	start := root
	if !path.Absolute {
		if !path.HasComponents() && !bool(shouldAllowEmptyPath) {
			return syserror.ENOENT
		}
		if dirfd == linux.AT_FDCWD {
			start = t.FSContext().WorkingDirectoryVFS2()
			defer start.DecRef()
		} else {
			dirfile := t.GetFileVFS2(dirfd)
			if dirfile == nil {
				return syserror.EBADF
			}
			if !path.HasComponents() {
				// Use FileDescription.SetStat() instead of
				// VirtualFilesystem.SetStatAt(), since the former may be able
				// to use opened file state to expedite the SetStat.
				err := dirfile.SetStat(t, *opts)
				dirfile.DecRef()
				return err
			}
			start = dirfile.VirtualDentry()
			start.IncRef()
			defer start.DecRef()
			dirfile.DecRef()
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
	if err == syserror.ErrExceedsFileSizeLimit {
		// Convert error to EFBIG and send a SIGXFSZ per setrlimit(2).
		t.SendSignal(kernel.SignalInfoNoInfo(linux.SIGXFSZ, t, t))
		return syserror.EFBIG
	}
	return err
}
