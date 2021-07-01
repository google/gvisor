// Copyright 2019 The gVisor Authors.
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
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// LINT.IfChange

// GetXattr implements linux syscall getxattr(2).
func GetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getXattrFromPath(t, args, true)
}

// LGetXattr implements linux syscall lgetxattr(2).
func LGetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getXattrFromPath(t, args, false)
}

// FGetXattr implements linux syscall fgetxattr(2).
func FGetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := uint64(args[3].SizeT())

	// TODO(b/113957122): Return EBADF if the fd was opened with O_PATH.
	f := t.GetFile(fd)
	if f == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer f.DecRef(t)

	n, err := getXattr(t, f.Dirent, nameAddr, valueAddr, size)
	if err != nil {
		return 0, nil, err
	}

	return uintptr(n), nil, nil
}

func getXattrFromPath(t *kernel.Task, args arch.SyscallArguments, resolveSymlink bool) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := uint64(args[3].SizeT())

	path, dirPath, err := copyInPath(t, pathAddr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	n := 0
	err = fileOpOn(t, linux.AT_FDCWD, path, resolveSymlink, func(_ *fs.Dirent, d *fs.Dirent, _ uint) error {
		if dirPath && !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		n, err = getXattr(t, d, nameAddr, valueAddr, size)
		return err
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(n), nil, nil
}

// getXattr implements getxattr(2) from the given *fs.Dirent.
func getXattr(t *kernel.Task, d *fs.Dirent, nameAddr, valueAddr hostarch.Addr, size uint64) (int, error) {
	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return 0, err
	}

	if err := checkXattrPermissions(t, d.Inode, fs.PermMask{Read: true}); err != nil {
		return 0, err
	}

	// TODO(b/148380782): Support xattrs in namespaces other than "user".
	if !strings.HasPrefix(name, linux.XATTR_USER_PREFIX) {
		return 0, syserror.EOPNOTSUPP
	}

	// If getxattr(2) is called with size 0, the size of the value will be
	// returned successfully even if it is nonzero. In that case, we need to
	// retrieve the entire attribute value so we can return the correct size.
	requestedSize := size
	if size == 0 || size > linux.XATTR_SIZE_MAX {
		requestedSize = linux.XATTR_SIZE_MAX
	}

	value, err := d.Inode.GetXattr(t, name, requestedSize)
	if err != nil {
		return 0, err
	}
	n := len(value)
	if uint64(n) > requestedSize {
		return 0, syserror.ERANGE
	}

	// Don't copy out the attribute value if size is 0.
	if size == 0 {
		return n, nil
	}

	if _, err = t.CopyOutBytes(valueAddr, []byte(value)); err != nil {
		return 0, err
	}
	return n, nil
}

// SetXattr implements linux syscall setxattr(2).
func SetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return setXattrFromPath(t, args, true)
}

// LSetXattr implements linux syscall lsetxattr(2).
func LSetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return setXattrFromPath(t, args, false)
}

// FSetXattr implements linux syscall fsetxattr(2).
func FSetXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := uint64(args[3].SizeT())
	flags := args[4].Uint()

	// TODO(b/113957122): Return EBADF if the fd was opened with O_PATH.
	f := t.GetFile(fd)
	if f == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer f.DecRef(t)

	return 0, nil, setXattr(t, f.Dirent, nameAddr, valueAddr, uint64(size), flags)
}

func setXattrFromPath(t *kernel.Task, args arch.SyscallArguments, resolveSymlink bool) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	nameAddr := args[1].Pointer()
	valueAddr := args[2].Pointer()
	size := uint64(args[3].SizeT())
	flags := args[4].Uint()

	path, dirPath, err := copyInPath(t, pathAddr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, resolveSymlink, func(_ *fs.Dirent, d *fs.Dirent, _ uint) error {
		if dirPath && !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		return setXattr(t, d, nameAddr, valueAddr, uint64(size), flags)
	})
}

// setXattr implements setxattr(2) from the given *fs.Dirent.
func setXattr(t *kernel.Task, d *fs.Dirent, nameAddr, valueAddr hostarch.Addr, size uint64, flags uint32) error {
	if flags&^(linux.XATTR_CREATE|linux.XATTR_REPLACE) != 0 {
		return linuxerr.EINVAL
	}

	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return err
	}

	if err := checkXattrPermissions(t, d.Inode, fs.PermMask{Write: true}); err != nil {
		return err
	}

	if size > linux.XATTR_SIZE_MAX {
		return linuxerr.E2BIG
	}
	buf := make([]byte, size)
	if _, err := t.CopyInBytes(valueAddr, buf); err != nil {
		return err
	}
	value := string(buf)

	if !strings.HasPrefix(name, linux.XATTR_USER_PREFIX) {
		return syserror.EOPNOTSUPP
	}

	if err := d.Inode.SetXattr(t, d, name, value, flags); err != nil {
		return err
	}
	d.InotifyEvent(linux.IN_ATTRIB, 0)
	return nil
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

// Restrict xattrs to regular files and directories.
//
// TODO(b/148380782): In Linux, this restriction technically only applies to
// xattrs in the "user.*" namespace. Make file type checks specific to the
// namespace once we allow other xattr prefixes.
func xattrFileTypeOk(i *fs.Inode) bool {
	return fs.IsRegular(i.StableAttr) || fs.IsDir(i.StableAttr)
}

func checkXattrPermissions(t *kernel.Task, i *fs.Inode, perms fs.PermMask) error {
	// Restrict xattrs to regular files and directories.
	if !xattrFileTypeOk(i) {
		if perms.Write {
			return linuxerr.EPERM
		}
		return linuxerr.ENODATA
	}

	return i.CheckPermission(t, perms)
}

// ListXattr implements linux syscall listxattr(2).
func ListXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return listXattrFromPath(t, args, true)
}

// LListXattr implements linux syscall llistxattr(2).
func LListXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return listXattrFromPath(t, args, false)
}

// FListXattr implements linux syscall flistxattr(2).
func FListXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	listAddr := args[1].Pointer()
	size := uint64(args[2].SizeT())

	// TODO(b/113957122): Return EBADF if the fd was opened with O_PATH.
	f := t.GetFile(fd)
	if f == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer f.DecRef(t)

	n, err := listXattr(t, f.Dirent, listAddr, size)
	if err != nil {
		return 0, nil, err
	}

	return uintptr(n), nil, nil
}

func listXattrFromPath(t *kernel.Task, args arch.SyscallArguments, resolveSymlink bool) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	listAddr := args[1].Pointer()
	size := uint64(args[2].SizeT())

	path, dirPath, err := copyInPath(t, pathAddr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	n := 0
	err = fileOpOn(t, linux.AT_FDCWD, path, resolveSymlink, func(_ *fs.Dirent, d *fs.Dirent, _ uint) error {
		if dirPath && !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		n, err = listXattr(t, d, listAddr, size)
		return err
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(n), nil, nil
}

func listXattr(t *kernel.Task, d *fs.Dirent, addr hostarch.Addr, size uint64) (int, error) {
	if !xattrFileTypeOk(d.Inode) {
		return 0, nil
	}

	// If listxattr(2) is called with size 0, the buffer size needed to contain
	// the xattr list will be returned successfully even if it is nonzero. In
	// that case, we need to retrieve the entire list so we can compute and
	// return the correct size.
	requestedSize := size
	if size == 0 || size > linux.XATTR_SIZE_MAX {
		requestedSize = linux.XATTR_SIZE_MAX
	}
	xattrs, err := d.Inode.ListXattr(t, requestedSize)
	if err != nil {
		return 0, err
	}

	// TODO(b/148380782): support namespaces other than "user".
	for x := range xattrs {
		if !strings.HasPrefix(x, linux.XATTR_USER_PREFIX) {
			delete(xattrs, x)
		}
	}

	listSize := xattrListSize(xattrs)
	if listSize > linux.XATTR_SIZE_MAX {
		return 0, linuxerr.E2BIG
	}
	if uint64(listSize) > requestedSize {
		return 0, syserror.ERANGE
	}

	// Don't copy out the attributes if size is 0.
	if size == 0 {
		return listSize, nil
	}

	buf := make([]byte, 0, listSize)
	for x := range xattrs {
		buf = append(buf, []byte(x)...)
		buf = append(buf, 0)
	}
	if _, err := t.CopyOutBytes(addr, buf); err != nil {
		return 0, err
	}

	return len(buf), nil
}

func xattrListSize(xattrs map[string]struct{}) int {
	size := 0
	for x := range xattrs {
		size += len(x) + 1
	}
	return size
}

// RemoveXattr implements linux syscall removexattr(2).
func RemoveXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return removeXattrFromPath(t, args, true)
}

// LRemoveXattr implements linux syscall lremovexattr(2).
func LRemoveXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return removeXattrFromPath(t, args, false)
}

// FRemoveXattr implements linux syscall fremovexattr(2).
func FRemoveXattr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	nameAddr := args[1].Pointer()

	// TODO(b/113957122): Return EBADF if the fd was opened with O_PATH.
	f := t.GetFile(fd)
	if f == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer f.DecRef(t)

	return 0, nil, removeXattr(t, f.Dirent, nameAddr)
}

func removeXattrFromPath(t *kernel.Task, args arch.SyscallArguments, resolveSymlink bool) (uintptr, *kernel.SyscallControl, error) {
	pathAddr := args[0].Pointer()
	nameAddr := args[1].Pointer()

	path, dirPath, err := copyInPath(t, pathAddr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, resolveSymlink, func(_ *fs.Dirent, d *fs.Dirent, _ uint) error {
		if dirPath && !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		return removeXattr(t, d, nameAddr)
	})
}

// removeXattr implements removexattr(2) from the given *fs.Dirent.
func removeXattr(t *kernel.Task, d *fs.Dirent, nameAddr hostarch.Addr) error {
	name, err := copyInXattrName(t, nameAddr)
	if err != nil {
		return err
	}

	if err := checkXattrPermissions(t, d.Inode, fs.PermMask{Write: true}); err != nil {
		return err
	}

	if !strings.HasPrefix(name, linux.XATTR_USER_PREFIX) {
		return syserror.EOPNOTSUPP
	}

	if err := d.Inode.RemoveXattr(t, d, name); err != nil {
		return err
	}
	d.InotifyEvent(linux.IN_ATTRIB, 0)
	return nil
}

// LINT.ThenChange(vfs2/xattr.go)
