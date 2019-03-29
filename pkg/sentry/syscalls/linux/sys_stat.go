// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Stat implements linux syscall stat(2).
func Stat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	statAddr := args[1].Pointer()

	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent) error {
		return stat(t, d, dirPath, statAddr)
	})
}

// Fstatat implements linux syscall newfstatat, i.e. fstatat(2).
func Fstatat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	statAddr := args[2].Pointer()
	flags := args[3].Int()

	path, dirPath, err := copyInPath(t, addr, flags&linux.AT_EMPTY_PATH != 0)
	if err != nil {
		return 0, nil, err
	}

	if path == "" {
		// Annoying. What's wrong with fstat?
		file := t.FDMap().GetFile(fd)
		if file == nil {
			return 0, nil, syserror.EBADF
		}
		defer file.DecRef()

		return 0, nil, stat(t, file.Dirent, false, statAddr)
	}

	return 0, nil, fileOpOn(t, fd, path, flags&linux.AT_SYMLINK_NOFOLLOW == 0, func(root *fs.Dirent, d *fs.Dirent) error {
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

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, resolve, func(root *fs.Dirent, d *fs.Dirent) error {
		return stat(t, d, dirPath, statAddr)
	})
}

// Fstat implements linux syscall fstat(2).
func Fstat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	statAddr := args[1].Pointer()

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, stat(t, file.Dirent, false /* dirPath */, statAddr)
}

// stat implements stat from the given *fs.Dirent.
func stat(t *kernel.Task, d *fs.Dirent, dirPath bool, statAddr usermem.Addr) error {
	if dirPath && !fs.IsDir(d.Inode.StableAttr) {
		return syserror.ENOTDIR
	}
	uattr, err := d.Inode.UnstableAttr(t)
	if err != nil {
		return err
	}

	var mode uint32
	switch d.Inode.StableAttr.Type {
	case fs.RegularFile, fs.SpecialFile:
		mode |= linux.ModeRegular
	case fs.Symlink:
		mode |= linux.ModeSymlink
	case fs.Directory, fs.SpecialDirectory:
		mode |= linux.ModeDirectory
	case fs.Pipe:
		mode |= linux.ModeNamedPipe
	case fs.CharacterDevice:
		mode |= linux.ModeCharacterDevice
	case fs.BlockDevice:
		mode |= linux.ModeBlockDevice
	case fs.Socket:
		mode |= linux.ModeSocket
	}

	// We encode the stat struct to bytes manually, as stat() is a very
	// common syscall for many applications, and t.CopyObjectOut has
	// noticeable performance impact due to its many slice allocations and
	// use of reflection.
	b := t.CopyScratchBuffer(int(linux.SizeOfStat))[:0]

	// Dev (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(d.Inode.StableAttr.DeviceID))
	// Ino (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(d.Inode.StableAttr.InodeID))
	// Nlink (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uattr.Links)
	// Mode (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, mode|uint32(uattr.Perms.LinuxMode()))
	// UID (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, uint32(uattr.Owner.UID.In(t.UserNamespace()).OrOverflow()))
	// GID (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, uint32(uattr.Owner.GID.In(t.UserNamespace()).OrOverflow()))
	// Padding (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, 0)
	// Rdev (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(linux.MakeDeviceID(d.Inode.StableAttr.DeviceFileMajor, d.Inode.StableAttr.DeviceFileMinor)))
	// Size (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(uattr.Size))
	// Blksize (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(d.Inode.StableAttr.BlockSize))
	// Blocks (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(uattr.Usage/512))

	// ATime
	atime := uattr.AccessTime.Timespec()
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(atime.Sec))
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(atime.Nsec))

	// MTime
	mtime := uattr.ModificationTime.Timespec()
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(mtime.Sec))
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(mtime.Nsec))

	// CTime
	ctime := uattr.StatusChangeTime.Timespec()
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(ctime.Sec))
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(ctime.Nsec))

	_, err = t.CopyOutBytes(statAddr, b)
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

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent) error {
		return statfsImpl(t, d, statfsAddr)
	})
}

// Fstatfs implements linux syscall fstatfs(2).
func Fstatfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	statfsAddr := args[1].Pointer()

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, statfsImpl(t, file.Dirent, statfsAddr)
}

// statfsImpl implements the linux syscall statfs and fstatfs based on a Dirent,
// copying the statfs structure out to addr on success, otherwise an error is
// returned.
func statfsImpl(t *kernel.Task, d *fs.Dirent, addr usermem.Addr) error {
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
	if _, err := t.CopyOut(addr, &statfs); err != nil {
		return err
	}
	return nil
}
