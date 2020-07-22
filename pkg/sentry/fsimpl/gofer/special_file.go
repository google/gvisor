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

package gofer

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// specialFileFD implements vfs.FileDescriptionImpl for pipes, sockets, device
// special files, and (when filesystemOptions.regularFilesUseSpecialFileFD is
// in effect) regular files. specialFileFD differs from regularFileFD by using
// per-FD handles instead of shared per-dentry handles, and never buffering I/O.
type specialFileFD struct {
	fileDescription

	// handle is used for file I/O. handle is immutable.
	handle handle

	// seekable is true if this file description represents a file for which
	// file offset is significant, i.e. a regular file. seekable is immutable.
	seekable bool

	// haveQueue is true if this file description represents a file for which
	// queue may send I/O readiness events. haveQueue is immutable.
	haveQueue bool
	queue     waiter.Queue

	// If seekable is true, off is the file offset. off is protected by mu.
	mu  sync.Mutex
	off int64
}

func newSpecialFileFD(h handle, mnt *vfs.Mount, d *dentry, locks *vfs.FileLocks, flags uint32) (*specialFileFD, error) {
	ftype := d.fileType()
	seekable := ftype == linux.S_IFREG
	haveQueue := (ftype == linux.S_IFIFO || ftype == linux.S_IFSOCK) && h.fd >= 0
	fd := &specialFileFD{
		handle:    h,
		seekable:  seekable,
		haveQueue: haveQueue,
	}
	fd.LockFD.Init(locks)
	if haveQueue {
		if err := fdnotifier.AddFD(h.fd, &fd.queue); err != nil {
			return nil, err
		}
	}
	if err := fd.vfsfd.Init(fd, flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{
		DenyPRead:  !seekable,
		DenyPWrite: !seekable,
	}); err != nil {
		if haveQueue {
			fdnotifier.RemoveFD(h.fd)
		}
		return nil, err
	}
	return fd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *specialFileFD) Release() {
	if fd.haveQueue {
		fdnotifier.RemoveFD(fd.handle.fd)
	}
	fd.handle.close(context.Background())
	fs := fd.vfsfd.Mount().Filesystem().Impl().(*filesystem)
	fs.syncMu.Lock()
	delete(fs.specialFileFDs, fd)
	fs.syncMu.Unlock()
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *specialFileFD) OnClose(ctx context.Context) error {
	if !fd.vfsfd.IsWritable() {
		return nil
	}
	return fd.handle.file.flush(ctx)
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *specialFileFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	if fd.haveQueue {
		return fdnotifier.NonBlockingPoll(fd.handle.fd, mask)
	}
	return fd.fileDescription.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *specialFileFD) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	if fd.haveQueue {
		fd.queue.EventRegister(e, mask)
		fdnotifier.UpdateFD(fd.handle.fd)
		return
	}
	fd.fileDescription.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *specialFileFD) EventUnregister(e *waiter.Entry) {
	if fd.haveQueue {
		fd.queue.EventUnregister(e)
		fdnotifier.UpdateFD(fd.handle.fd)
		return
	}
	fd.fileDescription.EventUnregister(e)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *specialFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if fd.seekable && offset < 0 {
		return 0, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	// Going through dst.CopyOutFrom() holds MM locks around file operations of
	// unknown duration. For regularFileFD, doing so is necessary to support
	// mmap due to lock ordering; MM locks precede dentry.dataMu. That doesn't
	// hold here since specialFileFD doesn't client-cache data. Just buffer the
	// read instead.
	if d := fd.dentry(); d.cachedMetadataAuthoritative() {
		d.touchAtime(fd.vfsfd.Mount())
	}
	buf := make([]byte, dst.NumBytes())
	n, err := fd.handle.readToBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), uint64(offset))
	if err == syserror.EAGAIN {
		err = syserror.ErrWouldBlock
	}
	if n == 0 {
		return 0, err
	}
	if cp, cperr := dst.CopyOut(ctx, buf[:n]); cperr != nil {
		return int64(cp), cperr
	}
	return int64(n), err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *specialFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if !fd.seekable {
		return fd.PRead(ctx, dst, -1, opts)
	}

	fd.mu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *specialFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// pwrite returns the number of bytes written, final offset, error. The final
// offset should be ignored by PWrite.
func (fd *specialFileFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if fd.seekable && offset < 0 {
		return 0, offset, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select pwritev2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, syserror.EOPNOTSUPP
	}

	d := fd.dentry()
	// If the regular file fd was opened with O_APPEND, make sure the file size
	// is updated. There is a possible race here if size is modified externally
	// after metadata cache is updated.
	if fd.seekable && fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 && !d.cachedMetadataAuthoritative() {
		if err := d.updateFromGetattr(ctx); err != nil {
			return 0, offset, err
		}
	}

	if fd.seekable {
		// We need to hold the metadataMu *while* writing to a regular file.
		d.metadataMu.Lock()
		defer d.metadataMu.Unlock()

		// Set offset to file size if the regular file was opened with O_APPEND.
		if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
			// Holding d.metadataMu is sufficient for reading d.size.
			offset = int64(d.size)
		}
		limit, err := vfs.CheckLimit(ctx, offset, src.NumBytes())
		if err != nil {
			return 0, offset, err
		}
		src = src.TakeFirst64(limit)
	}

	// Do a buffered write. See rationale in PRead.
	if d.cachedMetadataAuthoritative() {
		d.touchCMtime()
	}
	buf := make([]byte, src.NumBytes())
	// Don't do partial writes if we get a partial read from src.
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, offset, err
	}
	n, err := fd.handle.writeFromBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), uint64(offset))
	if err == syserror.EAGAIN {
		err = syserror.ErrWouldBlock
	}
	finalOff = offset
	// Update file size for regular files.
	if fd.seekable {
		finalOff += int64(n)
		// d.metadataMu is already locked at this point.
		if uint64(finalOff) > d.size {
			d.dataMu.Lock()
			defer d.dataMu.Unlock()
			atomic.StoreUint64(&d.size, uint64(finalOff))
		}
	}
	return int64(n), finalOff, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *specialFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if !fd.seekable {
		return fd.PWrite(ctx, src, -1, opts)
	}

	fd.mu.Lock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	fd.mu.Unlock()
	return n, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *specialFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if !fd.seekable {
		return 0, syserror.ESPIPE
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	newOffset, err := regularFileSeekLocked(ctx, fd.dentry(), fd.off, offset, whence)
	if err != nil {
		return 0, err
	}
	fd.off = newOffset
	return newOffset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *specialFileFD) Sync(ctx context.Context) error {
	return fd.dentry().syncSharedHandle(ctx)
}
