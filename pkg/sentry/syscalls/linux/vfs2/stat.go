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
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Stat implements Linux syscall stat(2).
func Stat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	statAddr := args[1].Pointer()
	return 0, nil, fstatat(t, linux.AT_FDCWD, pathAddr, statAddr, 0 /* flags */)
}

// Lstat implements Linux syscall lstat(2).
func Lstat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	statAddr := args[1].Pointer()
	return 0, nil, fstatat(t, linux.AT_FDCWD, pathAddr, statAddr, linux.AT_SYMLINK_NOFOLLOW)
}

// Newfstatat implements Linux syscall newfstatat, which backs fstatat(2).
func Newfstatat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	statAddr := args[2].Pointer()
	flags := args[3].Int()
	return 0, nil, fstatat(t, dirfd, pathAddr, statAddr, flags)
}

func fstatat(t *kernel.Task, dirfd int32, pathAddr, statAddr hostarch.Addr, flags int32) error {
	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW) != 0 {
		return linuxerr.EINVAL
	}

	opts := vfs.StatOptions{
		Mask: linux.STATX_BASIC_STATS,
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}

	root := t.FSContext().RootDirectoryVFS2()
	defer root.DecRef(t)
	start := root
	if !path.Absolute {
		if !path.HasComponents() && flags&linux.AT_EMPTY_PATH == 0 {
			return linuxerr.ENOENT
		}
		if dirfd == linux.AT_FDCWD {
			start = t.FSContext().WorkingDirectoryVFS2()
			defer start.DecRef(t)
		} else {
			dirfile := t.GetFileVFS2(dirfd)
			if dirfile == nil {
				return linuxerr.EBADF
			}
			if !path.HasComponents() {
				// Use FileDescription.Stat() instead of
				// VirtualFilesystem.StatAt() for fstatat(fd, ""), since the
				// former may be able to use opened file state to expedite the
				// Stat.
				statx, err := dirfile.Stat(t, opts)
				dirfile.DecRef(t)
				if err != nil {
					return err
				}
				var stat linux.Stat
				convertStatxToUserStat(t, &statx, &stat)
				_, err = stat.CopyOut(t, statAddr)
				return err
			}
			start = dirfile.VirtualDentry()
			start.IncRef()
			defer start.DecRef(t)
			dirfile.DecRef(t)
		}
	}

	statx, err := t.Kernel().VFS().StatAt(t, t.Credentials(), &vfs.PathOperation{
		Root:               root,
		Start:              start,
		Path:               path,
		FollowFinalSymlink: flags&linux.AT_SYMLINK_NOFOLLOW == 0,
	}, &opts)
	if err != nil {
		return err
	}
	var stat linux.Stat
	convertStatxToUserStat(t, &statx, &stat)
	_, err = stat.CopyOut(t, statAddr)
	return err
}

func timespecFromStatxTimestamp(sxts linux.StatxTimestamp) linux.Timespec {
	return linux.Timespec{
		Sec:  sxts.Sec,
		Nsec: int64(sxts.Nsec),
	}
}

// Fstat implements Linux syscall fstat(2).
func Fstat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	statAddr := args[1].Pointer()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	statx, err := file.Stat(t, vfs.StatOptions{
		Mask: linux.STATX_BASIC_STATS,
	})
	if err != nil {
		return 0, nil, err
	}
	var stat linux.Stat
	convertStatxToUserStat(t, &statx, &stat)
	_, err = stat.CopyOut(t, statAddr)
	return 0, nil, err
}

// Statx implements Linux syscall statx(2).
func Statx(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	flags := args[2].Int()
	mask := args[3].Uint()
	statxAddr := args[4].Pointer()

	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW|linux.AT_STATX_SYNC_TYPE) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	// Make sure that only one sync type option is set.
	syncType := uint32(flags & linux.AT_STATX_SYNC_TYPE)
	if syncType != 0 && !bits.IsPowerOfTwo32(syncType) {
		return 0, nil, linuxerr.EINVAL
	}
	if mask&linux.STATX__RESERVED != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	opts := vfs.StatOptions{
		Mask: mask,
		Sync: uint32(flags & linux.AT_STATX_SYNC_TYPE),
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}

	root := t.FSContext().RootDirectoryVFS2()
	defer root.DecRef(t)
	start := root
	if !path.Absolute {
		if !path.HasComponents() && flags&linux.AT_EMPTY_PATH == 0 {
			return 0, nil, linuxerr.ENOENT
		}
		if dirfd == linux.AT_FDCWD {
			start = t.FSContext().WorkingDirectoryVFS2()
			defer start.DecRef(t)
		} else {
			dirfile := t.GetFileVFS2(dirfd)
			if dirfile == nil {
				return 0, nil, linuxerr.EBADF
			}
			if !path.HasComponents() {
				// Use FileDescription.Stat() instead of
				// VirtualFilesystem.StatAt() for statx(fd, ""), since the
				// former may be able to use opened file state to expedite the
				// Stat.
				statx, err := dirfile.Stat(t, opts)
				dirfile.DecRef(t)
				if err != nil {
					return 0, nil, err
				}
				userifyStatx(t, &statx)
				_, err = statx.CopyOut(t, statxAddr)
				return 0, nil, err
			}
			start = dirfile.VirtualDentry()
			start.IncRef()
			defer start.DecRef(t)
			dirfile.DecRef(t)
		}
	}

	statx, err := t.Kernel().VFS().StatAt(t, t.Credentials(), &vfs.PathOperation{
		Root:               root,
		Start:              start,
		Path:               path,
		FollowFinalSymlink: flags&linux.AT_SYMLINK_NOFOLLOW == 0,
	}, &opts)
	if err != nil {
		return 0, nil, err
	}
	userifyStatx(t, &statx)
	_, err = statx.CopyOut(t, statxAddr)
	return 0, nil, err
}

func userifyStatx(t *kernel.Task, statx *linux.Statx) {
	userns := t.UserNamespace()
	statx.UID = uint32(auth.KUID(statx.UID).In(userns).OrOverflow())
	statx.GID = uint32(auth.KGID(statx.GID).In(userns).OrOverflow())
}

// Readlink implements Linux syscall readlink(2).
func Readlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	bufAddr := args[1].Pointer()
	size := args[2].SizeT()
	return readlinkat(t, linux.AT_FDCWD, pathAddr, bufAddr, size)
}

// Access implements Linux syscall access(2).
func Access(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := args[1].ModeT()

	return 0, nil, accessAt(t, linux.AT_FDCWD, addr, mode)
}

// Faccessat implements Linux syscall faccessat(2).
//
// Note that the faccessat() system call does not take a flags argument:
// "The raw faccessat() system call takes only the first three arguments. The
// AT_EACCESS and AT_SYMLINK_NOFOLLOW flags are actually implemented within
// the glibc wrapper function for faccessat().  If either of these flags is
// specified, then the wrapper function employs fstatat(2) to determine access
// permissions." - faccessat(2)
func Faccessat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	addr := args[1].Pointer()
	mode := args[2].ModeT()

	return 0, nil, accessAt(t, dirfd, addr, mode)
}

func accessAt(t *kernel.Task, dirfd int32, pathAddr hostarch.Addr, mode uint) error {
	const rOK = 4
	const wOK = 2
	const xOK = 1

	// Sanity check the mode.
	if mode&^(rOK|wOK|xOK) != 0 {
		return linuxerr.EINVAL
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)

	// access(2) and faccessat(2) check permissions using real
	// UID/GID, not effective UID/GID.
	//
	// "access() needs to use the real uid/gid, not the effective
	// uid/gid. We do this by temporarily clearing all FS-related
	// capabilities and switching the fsuid/fsgid around to the
	// real ones." -fs/open.c:faccessat
	creds := t.Credentials().Fork()
	creds.EffectiveKUID = creds.RealKUID
	creds.EffectiveKGID = creds.RealKGID
	if creds.EffectiveKUID.In(creds.UserNamespace) == auth.RootUID {
		creds.EffectiveCaps = creds.PermittedCaps
	} else {
		creds.EffectiveCaps = 0
	}

	return t.Kernel().VFS().AccessAt(t, creds, vfs.AccessTypes(mode), &tpop.pop)
}

// Readlinkat implements Linux syscall mknodat(2).
func Readlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathAddr := args[1].Pointer()
	bufAddr := args[2].Pointer()
	size := args[3].SizeT()
	return readlinkat(t, dirfd, pathAddr, bufAddr, size)
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

// Statfs implements Linux syscall statfs(2).
func Statfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	bufAddr := args[1].Pointer()

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	statfs, err := t.Kernel().VFS().StatFSAt(t, t.Credentials(), &tpop.pop)
	if err != nil {
		return 0, nil, err
	}
	_, err = statfs.CopyOut(t, bufAddr)
	return 0, nil, err
}

// Fstatfs implements Linux syscall fstatfs(2).
func Fstatfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	bufAddr := args[1].Pointer()

	tpop, err := getTaskPathOperation(t, fd, fspath.Path{}, allowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	statfs, err := t.Kernel().VFS().StatFSAt(t, t.Credentials(), &tpop.pop)
	if err != nil {
		return 0, nil, err
	}
	_, err = statfs.CopyOut(t, bufAddr)
	return 0, nil, err
}
