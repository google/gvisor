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

package host

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/secio"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

// fileOperations implements fs.FileOperations for a host file descriptor.
//
// +stateify savable
type fileOperations struct {
	fsutil.NoopRelease `state:"nosave"`

	// iops are the Inode operations for this file.
	iops *inodeOperations `state:"wait"`

	// a scratch buffer for reading directory entries.
	dirinfo *dirInfo `state:"nosave"`

	// dirCursor is the directory cursor.
	dirCursor string

	// allowIoctl determines whether ioctls should be passed through to the
	// host.
	allowIoctl bool
}

// fileOperations implements fs.FileOperations.
var _ fs.FileOperations = (*fileOperations)(nil)

// NewFile creates a new File backed by the provided host file descriptor. If
// NewFile succeeds, ownership of the fd is transferred to the returned File.
//
// The returned File cannot be saved, since there is no guarantee that the same
// fd will exist or represent the same file at time of restore. If such a
// guarantee does exist, use ImportFile instead.
func NewFile(ctx context.Context, fd int, mounter fs.FileOwner) (*fs.File, error) {
	return newFileFromDonatedFD(ctx, fd, mounter, false, false)
}

// ImportFile creates a new File backed by the provided host file descriptor.
// Unlike NewFile, the file descriptor used by the File is duped from fd to
// ensure that later changes to fd are not reflected by the fs.File.
//
// If the returned file is saved, it will be restored by re-importing the fd
// originally passed to ImportFile. It is the restorer's responsibility to
// ensure that the fd represents the same file.
func ImportFile(ctx context.Context, fd int, mounter fs.FileOwner, allowIoctl bool) (*fs.File, error) {
	return newFileFromDonatedFD(ctx, fd, mounter, true, allowIoctl)
}

// newFileFromDonatedFD returns an fs.File from a donated fd. If the fd is
// saveable, then saveable is true.
func newFileFromDonatedFD(ctx context.Context, donated int, mounter fs.FileOwner, saveable, allowIoctl bool) (*fs.File, error) {
	var s syscall.Stat_t
	if err := syscall.Fstat(donated, &s); err != nil {
		return nil, err
	}
	switch s.Mode & syscall.S_IFMT {
	case syscall.S_IFSOCK:
		flags, err := fileFlagsFromDonatedFD(donated)
		if err != nil {
			return nil, err
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
		flags, err := fileFlagsFromDonatedFD(donated)
		if err != nil {
			return nil, err
		}
		msrc := newMountSource(ctx, "/", mounter, &Filesystem{}, fs.MountSourceFlags{}, false /* dontTranslateOwnership */)
		inode, err := newInode(ctx, msrc, donated, saveable, true /* donated */)
		if err != nil {
			return nil, err
		}
		iops := inode.InodeOperations.(*inodeOperations)

		name := fmt.Sprintf("host:[%d]", inode.StableAttr.InodeID)
		dirent := fs.NewDirent(inode, name)
		defer dirent.DecRef()

		return newFile(ctx, dirent, flags, iops, allowIoctl), nil
	}
}

func fileFlagsFromDonatedFD(donated int) (fs.FileFlags, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(donated), syscall.F_GETFL, 0)
	if errno != 0 {
		log.Warningf("Failed to get file flags for donated fd %d (errno=%d)", donated, errno)
		return fs.FileFlags{}, syscall.EIO
	}
	accmode := flags & syscall.O_ACCMODE
	return fs.FileFlags{
		Direct:      flags&syscall.O_DIRECT != 0,
		NonBlocking: flags&syscall.O_NONBLOCK != 0,
		Sync:        flags&syscall.O_SYNC != 0,
		Append:      flags&syscall.O_APPEND != 0,
		Read:        accmode == syscall.O_RDONLY || accmode == syscall.O_RDWR,
		Write:       accmode == syscall.O_WRONLY || accmode == syscall.O_RDWR,
	}, nil
}

// newFile returns a new fs.File.
func newFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags, iops *inodeOperations, allowIoctl bool) *fs.File {
	if !iops.ReturnsWouldBlock() {
		// Allow reading/writing at an arbitrary offset for files
		// that support it.
		flags.Pread = true
		flags.Pwrite = true
	}
	return fs.NewFile(ctx, dirent, flags, &fileOperations{
		iops:       iops,
		allowIoctl: allowIoctl,
	})
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
	defer root.DecRef()
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &f.dirCursor,
	}
	return fs.DirentReaddir(ctx, file.Dirent, f, root, dirCtx, file.Offset())
}

// IterateDir implements fs.DirIterator.IterateDir.
func (f *fileOperations) IterateDir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	if f.dirinfo == nil {
		f.dirinfo = new(dirInfo)
		f.dirinfo.buf = make([]byte, usermem.PageSize)
	}
	entries, err := f.iops.readdirAll(f.dirinfo)
	if err != nil {
		return offset, err
	}
	count, err := fs.GenericReaddir(dirCtx, fs.NewSortedDentryMap(entries))
	return offset + count, err
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
			err = syserror.ErrWouldBlock
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
				err = syserror.ErrWouldBlock
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
		return syscall.Fsync(f.iops.fileState.FD())
	}
	panic("invalid sync type")
}

// Flush implements fs.FileOperations.Flush.
func (f *fileOperations) Flush(context.Context, *fs.File) error {
	// This is a no-op because flushing the resource backing this
	// file would mean closing it. We can't do that because other
	// open files may depend on the backing host fd.
	return nil
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (f *fileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	if !canMap(file.Dirent.Inode) {
		return syserror.ENODEV
	}
	return fsutil.GenericConfigureMMap(file, f.iops.cachingInodeOps, opts)
}

// Seek implements fs.FileOperations.Seek.
func (f *fileOperations) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return fsutil.SeekWithDirCursor(ctx, file, whence, offset, &f.dirCursor)
}

// Ioctl implements fs.FileOperations.Iocotl.
func (f *fileOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	if !f.allowIoctl {
		return 0, syserror.ENOTTY
	}
	// Ignore arg[0].  This is the real FD:
	fd := f.iops.fileState.FD()
	ioctl := args[1].Uint64()
	switch ioctl {
	case unix.TCGETS:
		termios, err := ioctlGetTermios(fd)
		if err != nil {
			return 0, err
		}
		_, err = usermem.CopyObjectOut(ctx, io, args[2].Pointer(), termios, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case unix.TCSETS, unix.TCSETSW:
		var termios linux.Termios
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &termios, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		err := ioctlSetTermios(fd, ioctl, &termios)
		return 0, err

	case unix.TIOCGPGRP:
		// Args: pid_t *argp
		// When successful, equivalent to *argp = tcgetpgrp(fd).
		// Get the process group ID of the foreground process group on
		// this terminal.

		t := kernel.TaskFromContext(ctx)
		if t == nil {
			panic(fmt.Sprintf("cannot get thread group from context %v", ctx))
		}
		tid := t.ThreadID()
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), &tid, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case unix.TIOCSPGRP:
		// Args: const pid_t *argp
		// Equivalent to tcsetpgrp(fd, *argp).
		// Set the foreground process group ID of this terminal.

		// Not much we can do with this one at the moment, so we just
		// lie and pretend everything is great. Bash and Sh seem fine
		// with this.
		log.Warningf("Ignoring application ioctl(TIOCSPGRP) call")
		return 0, nil

	case unix.TIOCGWINSZ:
		// Args: struct winsize *argp
		// Get window size.
		winsize, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		if err != nil {
			return 0, err
		}
		_, err = usermem.CopyObjectOut(ctx, io, args[2].Pointer(), winsize, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case unix.TIOCSWINSZ:
		// Args: const struct winsize *argp
		// Set window size.
		var winsize unix.Winsize
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &winsize, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &winsize)
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}
