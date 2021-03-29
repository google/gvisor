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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"

	"gvisor.dev/gvisor/pkg/hostarch"
)

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
		return syserror.EINVAL
	}
	if flags&linux.AT_EMPTY_PATH != 0 && !t.HasCapability(linux.CAP_DAC_READ_SEARCH) {
		return syserror.ENOENT
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

	fd, err := t.NewFDFromVFS2(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0,
	})
	return uintptr(fd), nil, err
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
		return 0, nil, syserror.EINVAL
	}

	if flags&linux.AT_REMOVEDIR != 0 {
		return 0, nil, rmdirat(t, dirfd, pathAddr)
	}
	return 0, nil, unlinkat(t, dirfd, pathAddr)
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
		return syserror.ENOENT
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
