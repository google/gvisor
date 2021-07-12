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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// LINT.IfChange

// Stat implements linux syscall stat(2).
func Stat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	statAddr := args[1].Pointer()

	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		return stat(t, d, dirPath, statAddr)
	})
}

// Fstatat implements linux syscall newfstatat, i.e. fstatat(2).
func Fstatat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	statAddr := args[2].Pointer()
	flags := args[3].Int()

	path, dirPath, err := copyInPath(t, addr, flags&linux.AT_EMPTY_PATH != 0)
	if err != nil {
		return 0, nil, err
	}

	if path == "" {
		// Annoying. What's wrong with fstat?
		file := t.GetFile(fd)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)

		return 0, nil, fstat(t, file, statAddr)
	}

	// If the path ends in a slash (i.e. dirPath is true) or if AT_SYMLINK_NOFOLLOW is unset,
	// then we must resolve the final component.
	resolve := dirPath || flags&linux.AT_SYMLINK_NOFOLLOW == 0

	return 0, nil, fileOpOn(t, fd, path, resolve, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		return stat(t, d, dirPath, statAddr)
	})
}

// Lstat implements linux syscall lstat(2).
func Lstat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	statAddr := args[1].Pointer()

	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	// If the path ends in a slash (i.e. dirPath is true), then we *do*
	// want to resolve the final component.
	resolve := dirPath

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, resolve, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		return stat(t, d, dirPath, statAddr)
	})
}

// Fstat implements linux syscall fstat(2).
func Fstat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	statAddr := args[1].Pointer()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	return 0, nil, fstat(t, file, statAddr)
}

// stat implements stat from the given *fs.Dirent.
func stat(t *kernel.Task, d *fs.Dirent, dirPath bool, statAddr hostarch.Addr) error {
	if dirPath && !fs.IsDir(d.Inode.StableAttr) {
		return linuxerr.ENOTDIR
	}
	uattr, err := d.Inode.UnstableAttr(t)
	if err != nil {
		return err
	}
	s := statFromAttrs(t, d.Inode.StableAttr, uattr)
	_, err = s.CopyOut(t, statAddr)
	return err
}

// fstat implements fstat for the given *fs.File.
func fstat(t *kernel.Task, f *fs.File, statAddr hostarch.Addr) error {
	uattr, err := f.UnstableAttr(t)
	if err != nil {
		return err
	}
	s := statFromAttrs(t, f.Dirent.Inode.StableAttr, uattr)
	_, err = s.CopyOut(t, statAddr)
	return err
}

// Statx implements linux syscall statx(2).
func Statx(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	pathAddr := args[1].Pointer()
	flags := args[2].Int()
	mask := args[3].Uint()
	statxAddr := args[4].Pointer()

	if mask&linux.STATX__RESERVED != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if flags&^(linux.AT_SYMLINK_NOFOLLOW|linux.AT_EMPTY_PATH|linux.AT_STATX_SYNC_TYPE) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if flags&linux.AT_STATX_SYNC_TYPE == linux.AT_STATX_SYNC_TYPE {
		return 0, nil, linuxerr.EINVAL
	}

	path, dirPath, err := copyInPath(t, pathAddr, flags&linux.AT_EMPTY_PATH != 0)
	if err != nil {
		return 0, nil, err
	}

	if path == "" {
		file := t.GetFile(fd)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)
		uattr, err := file.UnstableAttr(t)
		if err != nil {
			return 0, nil, err
		}
		return 0, nil, statx(t, file.Dirent.Inode.StableAttr, uattr, statxAddr)
	}

	resolve := dirPath || flags&linux.AT_SYMLINK_NOFOLLOW == 0

	return 0, nil, fileOpOn(t, fd, path, resolve, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		if dirPath && !fs.IsDir(d.Inode.StableAttr) {
			return linuxerr.ENOTDIR
		}
		uattr, err := d.Inode.UnstableAttr(t)
		if err != nil {
			return err
		}
		return statx(t, d.Inode.StableAttr, uattr, statxAddr)
	})
}

func statx(t *kernel.Task, sattr fs.StableAttr, uattr fs.UnstableAttr, statxAddr hostarch.Addr) error {
	// "[T]he kernel may return fields that weren't requested and may fail to
	// return fields that were requested, depending on what the backing
	// filesystem supports.
	// [...]
	// A filesystem may also fill in fields that the caller didn't ask for
	// if it has values for them available and the information is available
	// at no extra cost. If this happens, the corresponding bits will be
	// set in stx_mask." -- statx(2)
	//
	// We fill in all the values we have (which currently does not include
	// btime, see b/135608823), regardless of what the user asked for. The
	// STATX_BASIC_STATS mask indicates that all fields are present except
	// for btime.

	devMajor, devMinor := linux.DecodeDeviceID(uint32(sattr.DeviceID))
	s := linux.Statx{
		// TODO(b/135608823): Support btime, and then change this to
		// STATX_ALL to indicate presence of btime.
		Mask: linux.STATX_BASIC_STATS,

		// No attributes, and none supported.
		Attributes:     0,
		AttributesMask: 0,

		Blksize:   uint32(sattr.BlockSize),
		Nlink:     uint32(uattr.Links),
		UID:       uint32(uattr.Owner.UID.In(t.UserNamespace()).OrOverflow()),
		GID:       uint32(uattr.Owner.GID.In(t.UserNamespace()).OrOverflow()),
		Mode:      uint16(sattr.Type.LinuxType()) | uint16(uattr.Perms.LinuxMode()),
		Ino:       sattr.InodeID,
		Size:      uint64(uattr.Size),
		Blocks:    uint64(uattr.Usage) / 512,
		Atime:     uattr.AccessTime.StatxTimestamp(),
		Ctime:     uattr.StatusChangeTime.StatxTimestamp(),
		Mtime:     uattr.ModificationTime.StatxTimestamp(),
		RdevMajor: uint32(sattr.DeviceFileMajor),
		RdevMinor: sattr.DeviceFileMinor,
		DevMajor:  uint32(devMajor),
		DevMinor:  devMinor,
	}
	_, err := s.CopyOut(t, statxAddr)
	return err
}

// Statfs implements linux syscall statfs(2).
func Statfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	statfsAddr := args[1].Pointer()

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		return statfsImpl(t, d, statfsAddr)
	})
}

// Fstatfs implements linux syscall fstatfs(2).
func Fstatfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	statfsAddr := args[1].Pointer()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	return 0, nil, statfsImpl(t, file.Dirent, statfsAddr)
}

// statfsImpl implements the linux syscall statfs and fstatfs based on a Dirent,
// copying the statfs structure out to addr on success, otherwise an error is
// returned.
func statfsImpl(t *kernel.Task, d *fs.Dirent, addr hostarch.Addr) error {
	info, err := d.Inode.StatFS(t)
	if err != nil {
		return err
	}
	// Construct the statfs structure and copy it out.
	statfs := linux.Statfs{
		Type: info.Type,
		// Treat block size and fragment size as the same, as
		// most consumers of this structure will expect one
		// or the other to be filled in.
		BlockSize: d.Inode.StableAttr.BlockSize,
		Blocks:    info.TotalBlocks,
		// We don't have the concept of reserved blocks, so
		// report blocks free the same as available blocks.
		// This is a normal thing for filesystems, to do, see
		// udf, hugetlbfs, tmpfs, among others.
		BlocksFree:      info.FreeBlocks,
		BlocksAvailable: info.FreeBlocks,
		Files:           info.TotalFiles,
		FilesFree:       info.FreeFiles,
		// Same as Linux for simple_statfs, see fs/libfs.c.
		NameLength:   linux.NAME_MAX,
		FragmentSize: d.Inode.StableAttr.BlockSize,
		// Leave other fields 0 like simple_statfs does.
	}
	_, err = statfs.CopyOut(t, addr)
	return err
}

// LINT.ThenChange(vfs2/stat.go)
