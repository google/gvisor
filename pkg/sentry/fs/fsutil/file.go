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

package fsutil

import (
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// FileNoopRelease implements fs.FileOperations.Release for files that have no
// resources to release.
type FileNoopRelease struct{}

// Release is a no-op.
func (FileNoopRelease) Release(context.Context) {}

// SeekWithDirCursor is used to implement fs.FileOperations.Seek.  If dirCursor
// is not nil and the seek was on a directory, the cursor will be updated.
//
// Currently only seeking to 0 on a directory is supported.
//
// FIXME(b/33075855): Lift directory seeking limitations.
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
		// FIXME(b/34716638): This preserves existing
		// behavior but is not universally correct.
		return 0, nil
	}

	// Otherwise compute the new offset.
	switch whence {
	case fs.SeekSet:
		switch inode.StableAttr.Type {
		case fs.RegularFile, fs.SpecialFile, fs.BlockDevice:
			if offset < 0 {
				return current, linuxerr.EINVAL
			}
			return offset, nil
		case fs.Directory, fs.SpecialDirectory:
			if offset != 0 {
				return current, linuxerr.EINVAL
			}
			// SEEK_SET to 0 moves the directory "cursor" to the beginning.
			if dirCursor != nil {
				*dirCursor = ""
			}
			return 0, nil
		default:
			return current, linuxerr.EINVAL
		}
	case fs.SeekCurrent:
		switch inode.StableAttr.Type {
		case fs.RegularFile, fs.SpecialFile, fs.BlockDevice:
			if current+offset < 0 {
				return current, linuxerr.EINVAL
			}
			return current + offset, nil
		case fs.Directory, fs.SpecialDirectory:
			if offset != 0 {
				return current, linuxerr.EINVAL
			}
			return current, nil
		default:
			return current, linuxerr.EINVAL
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
				return current, linuxerr.EINVAL
			}
			return sz + offset, nil
		// FIXME(b/34778850): This is not universally correct.
		// Remove SpecialDirectory.
		case fs.SpecialDirectory:
			if offset != 0 {
				return current, linuxerr.EINVAL
			}
			// SEEK_END to 0 moves the directory "cursor" to the end.
			//
			// FIXME(b/35442290): The ensures that after the seek,
			// reading on the directory will get EOF. But it is not
			// correct in general because the directory can grow in
			// size; attempting to read those new entries will be
			// futile (EOF will always be the result).
			return fs.FileMaxOffset, nil
		default:
			return current, linuxerr.EINVAL
		}
	}

	// Not a valid seek request.
	return current, linuxerr.EINVAL
}

// FileGenericSeek implements fs.FileOperations.Seek for files that use a
// generic seek implementation.
type FileGenericSeek struct{}

// Seek implements fs.FileOperations.Seek.
func (FileGenericSeek) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return SeekWithDirCursor(ctx, file, whence, offset, nil)
}

// FileZeroSeek implements fs.FileOperations.Seek for files that maintain a
// constant zero-value offset and require a no-op Seek.
type FileZeroSeek struct{}

// Seek implements fs.FileOperations.Seek.
func (FileZeroSeek) Seek(context.Context, *fs.File, fs.SeekWhence, int64) (int64, error) {
	return 0, nil
}

// FileNoSeek implements fs.FileOperations.Seek to return EINVAL.
type FileNoSeek struct{}

// Seek implements fs.FileOperations.Seek.
func (FileNoSeek) Seek(context.Context, *fs.File, fs.SeekWhence, int64) (int64, error) {
	return 0, linuxerr.EINVAL
}

// FilePipeSeek implements fs.FileOperations.Seek and can be used for files
// that behave like pipes (seeking is not supported).
type FilePipeSeek struct{}

// Seek implements fs.FileOperations.Seek.
func (FilePipeSeek) Seek(context.Context, *fs.File, fs.SeekWhence, int64) (int64, error) {
	return 0, syserror.ESPIPE
}

// FileNotDirReaddir implements fs.FileOperations.Readdir for non-directories.
type FileNotDirReaddir struct{}

// Readdir implements fs.FileOperations.FileNotDirReaddir.
func (FileNotDirReaddir) Readdir(context.Context, *fs.File, fs.DentrySerializer) (int64, error) {
	return 0, syserror.ENOTDIR
}

// FileNoFsync implements fs.FileOperations.Fsync for files that don't support
// syncing.
type FileNoFsync struct{}

// Fsync implements fs.FileOperations.Fsync.
func (FileNoFsync) Fsync(context.Context, *fs.File, int64, int64, fs.SyncType) error {
	return linuxerr.EINVAL
}

// FileNoopFsync implements fs.FileOperations.Fsync for files that don't need
// to synced.
type FileNoopFsync struct{}

// Fsync implements fs.FileOperations.Fsync.
func (FileNoopFsync) Fsync(context.Context, *fs.File, int64, int64, fs.SyncType) error {
	return nil
}

// FileNoopFlush implements fs.FileOperations.Flush as a no-op.
type FileNoopFlush struct{}

// Flush implements fs.FileOperations.Flush.
func (FileNoopFlush) Flush(context.Context, *fs.File) error {
	return nil
}

// FileNoMMap implements fs.FileOperations.Mappable for files that cannot
// be memory mapped.
type FileNoMMap struct{}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (FileNoMMap) ConfigureMMap(context.Context, *fs.File, *memmap.MMapOpts) error {
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

// FileNoIoctl implements fs.FileOperations.Ioctl for files that don't
// implement the ioctl syscall.
type FileNoIoctl struct{}

// Ioctl implements fs.FileOperations.Ioctl.
func (FileNoIoctl) Ioctl(context.Context, *fs.File, usermem.IO, arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
}

// FileNoSplice implements fs.FileOperations.ReadFrom and
// fs.FileOperations.WriteTo for files that don't support splice.
type FileNoSplice struct{}

// WriteTo implements fs.FileOperations.WriteTo.
func (FileNoSplice) WriteTo(context.Context, *fs.File, io.Writer, int64, bool) (int64, error) {
	return 0, syserror.ENOSYS
}

// ReadFrom implements fs.FileOperations.ReadFrom.
func (FileNoSplice) ReadFrom(context.Context, *fs.File, io.Reader, int64) (int64, error) {
	return 0, syserror.ENOSYS
}

// DirFileOperations implements most of fs.FileOperations for directories,
// except for Readdir and UnstableAttr which the embedding type must implement.
type DirFileOperations struct {
	waiter.AlwaysReady
	FileGenericSeek
	FileNoIoctl
	FileNoMMap
	FileNoopFlush
	FileNoopFsync
	FileNoopRelease
	FileNoSplice
}

// Read implements fs.FileOperations.Read
func (*DirFileOperations) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EISDIR
}

// Write implements fs.FileOperations.Write.
func (*DirFileOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EISDIR
}

// StaticDirFileOperations implements fs.FileOperations for directories with
// static children.
//
// +stateify savable
type StaticDirFileOperations struct {
	DirFileOperations        `state:"nosave"`
	FileUseInodeUnstableAttr `state:"nosave"`

	// dentryMap is a SortedDentryMap used to implement Readdir.
	dentryMap *fs.SortedDentryMap

	// dirCursor contains the name of the last directory entry that was
	// serialized.
	dirCursor string
}

// NewStaticDirFileOperations returns a new StaticDirFileOperations that will
// iterate the given denty map.
func NewStaticDirFileOperations(dentries *fs.SortedDentryMap) *StaticDirFileOperations {
	return &StaticDirFileOperations{
		dentryMap: dentries,
	}
}

// IterateDir implements DirIterator.IterateDir.
func (sdfo *StaticDirFileOperations) IterateDir(ctx context.Context, d *fs.Dirent, dirCtx *fs.DirCtx, offset int) (int, error) {
	n, err := fs.GenericReaddir(dirCtx, sdfo.dentryMap)
	return offset + n, err
}

// Readdir implements fs.FileOperations.Readdir.
func (sdfo *StaticDirFileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	if root != nil {
		defer root.DecRef(ctx)
	}
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &sdfo.dirCursor,
	}
	return fs.DirentReaddir(ctx, file.Dirent, sdfo, root, dirCtx, file.Offset())
}

// NoReadWriteFile is a file that does not support reading or writing.
//
// +stateify savable
type NoReadWriteFile struct {
	waiter.AlwaysReady       `state:"nosave"`
	FileGenericSeek          `state:"nosave"`
	FileNoIoctl              `state:"nosave"`
	FileNoMMap               `state:"nosave"`
	FileNoopFsync            `state:"nosave"`
	FileNoopFlush            `state:"nosave"`
	FileNoopRelease          `state:"nosave"`
	FileNoRead               `state:"nosave"`
	FileNoWrite              `state:"nosave"`
	FileNotDirReaddir        `state:"nosave"`
	FileUseInodeUnstableAttr `state:"nosave"`
	FileNoSplice             `state:"nosave"`
}

var _ fs.FileOperations = (*NoReadWriteFile)(nil)

// FileStaticContentReader is a helper to implement fs.FileOperations.Read with
// static content.
//
// +stateify savable
type FileStaticContentReader struct {
	// content is immutable.
	content []byte
}

// NewFileStaticContentReader initializes a FileStaticContentReader with the
// given content.
func NewFileStaticContentReader(b []byte) FileStaticContentReader {
	return FileStaticContentReader{
		content: b,
	}
}

// Read implements fs.FileOperations.Read.
func (scr *FileStaticContentReader) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	if offset >= int64(len(scr.content)) {
		return 0, nil
	}
	n, err := dst.CopyOut(ctx, scr.content[offset:])
	return int64(n), err
}

// FileNoopWrite implements fs.FileOperations.Write as a noop.
type FileNoopWrite struct{}

// Write implements fs.FileOperations.Write.
func (FileNoopWrite) Write(_ context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	return src.NumBytes(), nil
}

// FileNoRead implements fs.FileOperations.Read to return EINVAL.
type FileNoRead struct{}

// Read implements fs.FileOperations.Read.
func (FileNoRead) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, linuxerr.EINVAL
}

// FileNoWrite implements fs.FileOperations.Write to return EINVAL.
type FileNoWrite struct{}

// Write implements fs.FileOperations.Write.
func (FileNoWrite) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, linuxerr.EINVAL
}

// FileNoopRead implement fs.FileOperations.Read as a noop.
type FileNoopRead struct{}

// Read implements fs.FileOperations.Read.
func (FileNoopRead) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, nil
}

// FileUseInodeUnstableAttr implements fs.FileOperations.UnstableAttr by calling
// InodeOperations.UnstableAttr.
type FileUseInodeUnstableAttr struct{}

// UnstableAttr implements fs.FileOperations.UnstableAttr.
func (FileUseInodeUnstableAttr) UnstableAttr(ctx context.Context, file *fs.File) (fs.UnstableAttr, error) {
	return file.Dirent.Inode.UnstableAttr(ctx)
}
