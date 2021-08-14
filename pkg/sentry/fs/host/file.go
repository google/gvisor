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

package host

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/secio"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// fileOperations implements fs.FileOperations for a host file descriptor.
//
// +stateify savable
type fileOperations struct {
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosplice"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// iops are the Inode operations for this file.
	iops *inodeOperations `state:"wait"`

	// a scratch buffer for reading directory entries.
	dirinfo *dirInfo `state:"nosave"`

	// dirCursor is the directory cursor.
	dirCursor string
}

// fileOperations implements fs.FileOperations.
var _ fs.FileOperations = (*fileOperations)(nil)

// NewFile creates a new File backed by the provided host file descriptor. If
// NewFile succeeds, ownership of the FD is transferred to the returned File.
//
// The returned File cannot be saved, since there is no guarantee that the same
// FD will exist or represent the same file at time of restore. If such a
// guarantee does exist, use ImportFile instead.
func NewFile(ctx context.Context, fd int) (*fs.File, error) {
	return newFileFromDonatedFD(ctx, fd, false, false)
}

// ImportFile creates a new File backed by the provided host file descriptor.
// Unlike NewFile, the file descriptor used by the File is duped from FD to
// ensure that later changes to FD are not reflected by the fs.File.
//
// If the returned file is saved, it will be restored by re-importing the FD
// originally passed to ImportFile. It is the restorer's responsibility to
// ensure that the FD represents the same file.
func ImportFile(ctx context.Context, fd int, isTTY bool) (*fs.File, error) {
	return newFileFromDonatedFD(ctx, fd, true, isTTY)
}

// newFileFromDonatedFD returns an fs.File from a donated FD. If the FD is
// saveable, then saveable is true.
func newFileFromDonatedFD(ctx context.Context, donated int, saveable, isTTY bool) (*fs.File, error) {
	var s unix.Stat_t
	if err := unix.Fstat(donated, &s); err != nil {
		return nil, err
	}
	flags, err := fileFlagsFromDonatedFD(donated)
	if err != nil {
		return nil, err
	}
	switch s.Mode & unix.S_IFMT {
	case unix.S_IFSOCK:
		if isTTY {
			return nil, fmt.Errorf("cannot import host socket as TTY")
		}

		s, err := newSocket(ctx, donated, saveable)
		if err != nil {
			return nil, err
		}
		s.SetFlags(fs.SettableFileFlags{
			NonBlocking: flags.NonBlocking,
		})
		return s, nil
	default:
		msrc := fs.NewNonCachingMountSource(ctx, &filesystem{}, fs.MountSourceFlags{})
		inode, err := newInode(ctx, msrc, donated, saveable)
		if err != nil {
			return nil, err
		}
		iops := inode.InodeOperations.(*inodeOperations)

		name := fmt.Sprintf("host:[%d]", inode.StableAttr.InodeID)
		dirent := fs.NewDirent(ctx, inode, name)
		defer dirent.DecRef(ctx)

		if isTTY {
			return newTTYFile(ctx, dirent, flags, iops), nil
		}

		return newFile(ctx, dirent, flags, iops), nil
	}
}

func fileFlagsFromDonatedFD(donated int) (fs.FileFlags, error) {
	flags, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(donated), unix.F_GETFL, 0)
	if errno != 0 {
		log.Warningf("Failed to get file flags for donated FD %d (errno=%d)", donated, errno)
		return fs.FileFlags{}, unix.EIO
	}
	accmode := flags & unix.O_ACCMODE
	return fs.FileFlags{
		Direct:      flags&unix.O_DIRECT != 0,
		NonBlocking: flags&unix.O_NONBLOCK != 0,
		Sync:        flags&unix.O_SYNC != 0,
		Append:      flags&unix.O_APPEND != 0,
		Read:        accmode == unix.O_RDONLY || accmode == unix.O_RDWR,
		Write:       accmode == unix.O_WRONLY || accmode == unix.O_RDWR,
	}, nil
}

// newFile returns a new fs.File.
func newFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags, iops *inodeOperations) *fs.File {
	if !iops.ReturnsWouldBlock() {
		// Allow reading/writing at an arbitrary offset for files
		// that support it.
		flags.Pread = true
		flags.Pwrite = true
	}
	return fs.NewFile(ctx, dirent, flags, &fileOperations{iops: iops})
}

// EventRegister implements waiter.Waitable.EventRegister.
func (f *fileOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	f.iops.fileState.queue.EventRegister(e, mask)
	fdnotifier.UpdateFD(int32(f.iops.fileState.FD()))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (f *fileOperations) EventUnregister(e *waiter.Entry) {
	f.iops.fileState.queue.EventUnregister(e)
	fdnotifier.UpdateFD(int32(f.iops.fileState.FD()))
}

// Readiness uses the poll() syscall to check the status of the underlying FD.
func (f *fileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(int32(f.iops.fileState.FD()), mask)
}

// Readdir implements fs.FileOperations.Readdir.
func (f *fileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	if root != nil {
		defer root.DecRef(ctx)
	}
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &f.dirCursor,
	}
	return fs.DirentReaddir(ctx, file.Dirent, f, root, dirCtx, file.Offset())
}

// IterateDir implements fs.DirIterator.IterateDir.
func (f *fileOperations) IterateDir(ctx context.Context, d *fs.Dirent, dirCtx *fs.DirCtx, offset int) (int, error) {
	// We only support non-directory file descriptors that have been
	// imported, so just claim that this isn't a directory, even if it is.
	return offset, unix.ENOTDIR
}

// Write implements fs.FileOperations.Write.
func (f *fileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	// Would this file block?
	if f.iops.ReturnsWouldBlock() {
		// These files can't be memory mapped, assert this. This also
		// means that writes do not need to synchronize with memory
		// mappings nor metadata cached by this file's fs.Inode.
		if canMap(file.Dirent.Inode) {
			panic("files that can return EWOULDBLOCK cannot be memory mapped")
		}
		// Ignore the offset, these files don't support writing at
		// an arbitrary offset.
		writer := fd.NewReadWriter(f.iops.fileState.FD())
		n, err := src.CopyInTo(ctx, safemem.FromIOWriter{writer})
		if isBlockError(err) {
			err = linuxerr.ErrWouldBlock
		}
		return n, err
	}
	if !file.Dirent.Inode.MountSource.Flags.ForcePageCache {
		writer := secio.NewOffsetWriter(fd.NewReadWriter(f.iops.fileState.FD()), offset)
		return src.CopyInTo(ctx, safemem.FromIOWriter{writer})
	}
	return f.iops.cachingInodeOps.Write(ctx, src, offset)
}

// Read implements fs.FileOperations.Read.
func (f *fileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	// Would this file block?
	if f.iops.ReturnsWouldBlock() {
		// These files can't be memory mapped, assert this. This also
		// means that reads do not need to synchronize with memory
		// mappings nor metadata cached by this file's fs.Inode.
		if canMap(file.Dirent.Inode) {
			panic("files that can return EWOULDBLOCK cannot be memory mapped")
		}
		// Ignore the offset, these files don't support reading at
		// an arbitrary offset.
		reader := fd.NewReadWriter(f.iops.fileState.FD())
		n, err := dst.CopyOutFrom(ctx, safemem.FromIOReader{reader})
		if isBlockError(err) {
			// If we got any data at all, return it as a "completed" partial read
			// rather than retrying until complete.
			if n != 0 {
				err = nil
			} else {
				err = linuxerr.ErrWouldBlock
			}
		}
		return n, err
	}
	if !file.Dirent.Inode.MountSource.Flags.ForcePageCache {
		reader := secio.NewOffsetReader(fd.NewReadWriter(f.iops.fileState.FD()), offset)
		return dst.CopyOutFrom(ctx, safemem.FromIOReader{reader})
	}
	return f.iops.cachingInodeOps.Read(ctx, file, dst, offset)
}

// Fsync implements fs.FileOperations.Fsync.
func (f *fileOperations) Fsync(ctx context.Context, file *fs.File, start int64, end int64, syncType fs.SyncType) error {
	switch syncType {
	case fs.SyncAll, fs.SyncData:
		if err := file.Dirent.Inode.WriteOut(ctx); err != nil {
			return err
		}
		fallthrough
	case fs.SyncBackingStorage:
		return unix.Fsync(f.iops.fileState.FD())
	}
	panic("invalid sync type")
}

// Flush implements fs.FileOperations.Flush.
func (f *fileOperations) Flush(context.Context, *fs.File) error {
	// This is a no-op because flushing the resource backing this
	// file would mean closing it. We can't do that because other
	// open files may depend on the backing host FD.
	return nil
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (f *fileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	if !canMap(file.Dirent.Inode) {
		return linuxerr.ENODEV
	}
	return fsutil.GenericConfigureMMap(file, f.iops.cachingInodeOps, opts)
}

// Seek implements fs.FileOperations.Seek.
func (f *fileOperations) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return fsutil.SeekWithDirCursor(ctx, file, whence, offset, &f.dirCursor)
}
