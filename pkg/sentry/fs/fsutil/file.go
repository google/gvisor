// Copyright 2018 Google Inc.
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

package fsutil

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// NoopRelease implements FileOperations.Release for files that have no
// resources to release.
type NoopRelease struct{}

// Release is a no-op.
func (NoopRelease) Release() {}

// SeekWithDirCursor is used to implement fs.FileOperations.Seek.  If dirCursor
// is not nil and the seek was on a directory, the cursor will be updated.
//
// Currenly only seeking to 0 on a directory is supported.
//
// FIXME: Lift directory seeking limitations.
func SeekWithDirCursor(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64, dirCursor *string) (int64, error) {
	inode := file.Dirent.Inode
	current := file.Offset()

	// Does the Inode represents a non-seekable type?
	if fs.IsPipe(inode.StableAttr) || fs.IsSocket(inode.StableAttr) {
		return current, syserror.ESPIPE
	}

	// Does the Inode represent a character device?
	if fs.IsCharDevice(inode.StableAttr) {
		// Ignore seek requests.
		//
		// FIXME: This preserves existing
		// behavior but is not universally correct.
		return 0, nil
	}

	// Otherwise compute the new offset.
	switch whence {
	case fs.SeekSet:
		switch inode.StableAttr.Type {
		case fs.RegularFile, fs.SpecialFile, fs.BlockDevice:
			if offset < 0 {
				return current, syserror.EINVAL
			}
			return offset, nil
		case fs.Directory, fs.SpecialDirectory:
			if offset != 0 {
				return current, syserror.EINVAL
			}
			// SEEK_SET to 0 moves the directory "cursor" to the beginning.
			if dirCursor != nil {
				*dirCursor = ""
			}
			return 0, nil
		default:
			return current, syserror.EINVAL
		}
	case fs.SeekCurrent:
		switch inode.StableAttr.Type {
		case fs.RegularFile, fs.SpecialFile, fs.BlockDevice:
			if current+offset < 0 {
				return current, syserror.EINVAL
			}
			return current + offset, nil
		case fs.Directory, fs.SpecialDirectory:
			if offset != 0 {
				return current, syserror.EINVAL
			}
			return current, nil
		default:
			return current, syserror.EINVAL
		}
	case fs.SeekEnd:
		switch inode.StableAttr.Type {
		case fs.RegularFile, fs.BlockDevice:
			// Allow the file to determine the end.
			uattr, err := inode.UnstableAttr(ctx)
			if err != nil {
				return current, err
			}
			sz := uattr.Size
			if sz+offset < 0 {
				return current, syserror.EINVAL
			}
			return sz + offset, nil
		// FIXME: This is not universally correct.
		// Remove SpecialDirectory.
		case fs.SpecialDirectory:
			if offset != 0 {
				return current, syserror.EINVAL
			}
			// SEEK_END to 0 moves the directory "cursor" to the end.
			//
			// FIXME: The ensures that after the seek,
			// reading on the directory will get EOF. But it is not
			// correct in general because the directory can grow in
			// size; attempting to read those new entries will be
			// futile (EOF will always be the result).
			return fs.FileMaxOffset, nil
		default:
			return current, syserror.EINVAL
		}
	}

	// Not a valid seek request.
	return current, syserror.EINVAL
}

// GenericSeek implements FileOperations.Seek for files that use a generic
// seek implementation.
type GenericSeek struct{}

// Seek implements fs.FileOperations.Seek.
func (GenericSeek) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return SeekWithDirCursor(ctx, file, whence, offset, nil)
}

// ZeroSeek implements FileOperations.Seek for files that maintain a constant
// zero-value offset and require a no-op Seek.
type ZeroSeek struct{}

// Seek implements FileOperations.Seek.
func (ZeroSeek) Seek(context.Context, *fs.File, fs.SeekWhence, int64) (int64, error) {
	return 0, nil
}

// PipeSeek implements FileOperations.Seek and can be used for files that behave
// like pipes (seeking is not supported).
type PipeSeek struct{}

// Seek implements FileOperations.Seek.
func (PipeSeek) Seek(context.Context, *fs.File, fs.SeekWhence, int64) (int64, error) {
	return 0, syserror.ESPIPE
}

// NotDirReaddir implements FileOperations.Readdir for non-directories.
type NotDirReaddir struct{}

// Readdir implements FileOperations.NotDirReaddir.
func (NotDirReaddir) Readdir(context.Context, *fs.File, fs.DentrySerializer) (int64, error) {
	return 0, syserror.ENOTDIR
}

// NoFsync implements FileOperations.Fsync for files that don't support syncing.
type NoFsync struct{}

// Fsync implements FileOperations.Fsync.
func (NoFsync) Fsync(context.Context, *fs.File, int64, int64, fs.SyncType) error {
	return syserror.EINVAL
}

// NoopFsync implements FileOperations.Fsync for files that don't need to synced.
type NoopFsync struct{}

// Fsync implements FileOperations.Fsync.
func (NoopFsync) Fsync(context.Context, *fs.File, int64, int64, fs.SyncType) error {
	return nil
}

// NoopFlush implements FileOperations.Flush as a no-op.
type NoopFlush struct{}

// Flush implements FileOperations.Flush.
func (NoopFlush) Flush(context.Context, *fs.File) error {
	return nil
}

// NoMMap implements fs.FileOperations.Mappable for files that cannot
// be memory mapped.
type NoMMap struct{}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (NoMMap) ConfigureMMap(context.Context, *fs.File, *memmap.MMapOpts) error {
	return syserror.ENODEV
}

// GenericConfigureMMap implements fs.FileOperations.ConfigureMMap for most
// filesystems that support memory mapping.
func GenericConfigureMMap(file *fs.File, m memmap.Mappable, opts *memmap.MMapOpts) error {
	opts.Mappable = m
	opts.MappingIdentity = file
	file.IncRef()
	return nil
}

// NoIoctl implements fs.FileOperations.Ioctl for files that don't implement
// the ioctl syscall.
type NoIoctl struct{}

// Ioctl implements fs.FileOperations.Ioctl.
func (NoIoctl) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
}

// DirFileOperations implements FileOperations for directories.
type DirFileOperations struct {
	waiter.AlwaysReady `state:"nosave"`
	NoopRelease        `state:"nosave"`
	GenericSeek        `state:"nosave"`
	NoFsync            `state:"nosave"`
	NoopFlush          `state:"nosave"`
	NoMMap             `state:"nosave"`
	NoIoctl            `state:"nosave"`

	// dentryMap is a SortedDentryMap used to implement Readdir.
	dentryMap *fs.SortedDentryMap

	// dirCursor contains the name of the last directory entry that was
	// serialized.
	dirCursor string
}

// NewDirFileOperations returns a new DirFileOperations that will iterate the
// given denty map.
func NewDirFileOperations(dentries *fs.SortedDentryMap) *DirFileOperations {
	return &DirFileOperations{
		dentryMap: dentries,
	}
}

// IterateDir implements DirIterator.IterateDir.
func (dfo *DirFileOperations) IterateDir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	n, err := fs.GenericReaddir(dirCtx, dfo.dentryMap)
	return offset + n, err
}

// Readdir implements FileOperations.Readdir.
func (dfo *DirFileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	defer root.DecRef()
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &dfo.dirCursor,
	}
	return fs.DirentReaddir(ctx, file.Dirent, dfo, root, dirCtx, file.Offset())
}

// Read implements FileOperations.Read
func (*DirFileOperations) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EISDIR
}

// Write implements FileOperations.Write.
func (*DirFileOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EISDIR
}
