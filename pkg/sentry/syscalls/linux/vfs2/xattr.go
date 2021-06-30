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
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// ListXattr implements Linux syscall listxattr(2).
func ListXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return listxattr(t, args, followFinalSymlink)
}

// Llistxattr implements Linux syscall llistxattr(2).
func Llistxattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return listxattr(t, args, nofollowFinalSymlink)
}

func listxattr(t *kernel.Task, args arch.SyscallArguments, shouldFollowFinalSymlink shouldFollowFinalSymlink) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	listAddr := args[1].Pointer()
	size := args[2].SizeT()

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, shouldFollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	names, err := t.Kernel().VFS().ListXattrAt(t, t.Credentials(), &tpop.pop, uint64(size))
	if err != nil {
		return 0, nil, err
	}
	n, err := copyOutXattrNameList(t, listAddr, size, names)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// Flistxattr implements Linux syscall flistxattr(2).
func Flistxattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	listAddr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	names, err := file.ListXattr(t, uint64(size))
	if err != nil {
		return 0, nil, err
	}
	n, err := copyOutXattrNameList(t, listAddr, size, names)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// GetXattr implements Linux syscall getxattr(2).
func GetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getxattr(t, args, followFinalSymlink)
}

// Lgetxattr implements Linux syscall lgetxattr(2).
func Lgetxattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getxattr(t, args, nofollowFinalSymlink)
}

func getxattr(t *kernel.Task, args arch.SyscallArguments, shouldFollowFinalSymlink shouldFollowFinalSymlink) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := args[3].SizeT()

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, shouldFollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return 0, nil, err
	}

	value, err := t.Kernel().VFS().GetXattrAt(t, t.Credentials(), &tpop.pop, &vfs.GetXattrOptions{
		Name: name,
		Size: uint64(size),
	})
	if err != nil {
		return 0, nil, err
	}
	n, err := copyOutXattrValue(t, valueAddr, size, value)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// Fgetxattr implements Linux syscall fgetxattr(2).
func Fgetxattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := args[3].SizeT()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return 0, nil, err
	}

	value, err := file.GetXattr(t, &vfs.GetXattrOptions{Name: name, Size: uint64(size)})
	if err != nil {
		return 0, nil, err
	}
	n, err := copyOutXattrValue(t, valueAddr, size, value)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// SetXattr implements Linux syscall setxattr(2).
func SetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, setxattr(t, args, followFinalSymlink)
}

// Lsetxattr implements Linux syscall lsetxattr(2).
func Lsetxattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, setxattr(t, args, nofollowFinalSymlink)
}

func setxattr(t *kernel.Task, args arch.SyscallArguments, shouldFollowFinalSymlink shouldFollowFinalSymlink) error {
	pathAddr := args[0].Pointer()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := args[3].SizeT()
	flags := args[4].Int()

	if flags&^(linux.XATTR_CREATE|linux.XATTR_REPLACE) != 0 {
		return linuxerr.EINVAL
	}

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, shouldFollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return err
	}
	value, err := copyInXattrValue(t, valueAddr, size)
	if err != nil {
		return err
	}

	return t.Kernel().VFS().SetXattrAt(t, t.Credentials(), &tpop.pop, &vfs.SetXattrOptions{
		Name:  name,
		Value: value,
		Flags: uint32(flags),
	})
}

// Fsetxattr implements Linux syscall fsetxattr(2).
func Fsetxattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := args[3].SizeT()
	flags := args[4].Int()

	if flags&^(linux.XATTR_CREATE|linux.XATTR_REPLACE) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return 0, nil, err
	}
	value, err := copyInXattrValue(t, valueAddr, size)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, file.SetXattr(t, &vfs.SetXattrOptions{
		Name:  name,
		Value: value,
		Flags: uint32(flags),
	})
}

// RemoveXattr implements Linux syscall removexattr(2).
func RemoveXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, removexattr(t, args, followFinalSymlink)
}

// Lremovexattr implements Linux syscall lremovexattr(2).
func Lremovexattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, removexattr(t, args, nofollowFinalSymlink)
}

func removexattr(t *kernel.Task, args arch.SyscallArguments, shouldFollowFinalSymlink shouldFollowFinalSymlink) error {
	pathAddr := args[0].Pointer()
	nameAddr := args[1].Pointer()

	path, err := copyInPath(t, pathAddr)
	if err != nil {
		return err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, shouldFollowFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return err
	}

	return t.Kernel().VFS().RemoveXattrAt(t, t.Credentials(), &tpop.pop, name)
}

// Fremovexattr implements Linux syscall fremovexattr(2).
func Fremovexattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	nameAddr := args[1].Pointer()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, file.RemoveXattr(t, name)
}

func copyInXattrName(t *kernel.Task, nameAddr hostarch.Addr) (string, error) {
	name, err := t.CopyInString(nameAddr, linux.XATTR_NAME_MAX+1)
	if err != nil {
		if linuxerr.Equals(linuxerr.ENAMETOOLONG, err) {
			return "", syserror.ERANGE
		}
		return "", err
	}
	if len(name) == 0 {
		return "", syserror.ERANGE
	}
	return name, nil
}

func copyOutXattrNameList(t *kernel.Task, listAddr hostarch.Addr, size uint, names []string) (int, error) {
	if size > linux.XATTR_LIST_MAX {
		size = linux.XATTR_LIST_MAX
	}
	var buf bytes.Buffer
	for _, name := range names {
		buf.WriteString(name)
		buf.WriteByte(0)
	}
	if size == 0 {
		// Return the size that would be required to accomodate the list.
		return buf.Len(), nil
	}
	if buf.Len() > int(size) {
		if size >= linux.XATTR_LIST_MAX {
			return 0, linuxerr.E2BIG
		}
		return 0, syserror.ERANGE
	}
	return t.CopyOutBytes(listAddr, buf.Bytes())
}

func copyInXattrValue(t *kernel.Task, valueAddr hostarch.Addr, size uint) (string, error) {
	if size > linux.XATTR_SIZE_MAX {
		return "", linuxerr.E2BIG
	}
	buf := make([]byte, size)
	if _, err := t.CopyInBytes(valueAddr, buf); err != nil {
		return "", err
	}
	return gohacks.StringFromImmutableBytes(buf), nil
}

func copyOutXattrValue(t *kernel.Task, valueAddr hostarch.Addr, size uint, value string) (int, error) {
	if size > linux.XATTR_SIZE_MAX {
		size = linux.XATTR_SIZE_MAX
	}
	if size == 0 {
		// Return the size that would be required to accomodate the value.
		return len(value), nil
	}
	if len(value) > int(size) {
		if size >= linux.XATTR_SIZE_MAX {
			return 0, linuxerr.E2BIG
		}
		return 0, syserror.ERANGE
	}
	return t.CopyOutBytes(valueAddr, gohacks.ImmutableBytesFromString(value))
}
