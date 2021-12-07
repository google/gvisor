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
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// specialFileFD implements vfs.FileDescriptionImpl for pipes, sockets, device
// special files, and (when filesystemOptions.regularFilesUseSpecialFileFD is
// in effect) regular files. specialFileFD differs from regularFileFD by using
// per-FD handles instead of shared per-dentry handles, and never buffering I/O.
//
// +stateify savable
type specialFileFD struct {
	fileDescription

	// releaseMu synchronizes the closing of fd.handle with fd.sync(). It's safe
	// to access fd.handle without locking for operations that require a ref to
	// be held by the caller, e.g. vfs.FileDescriptionImpl implementations.
	releaseMu sync.RWMutex `state:"nosave"`

	// handle is used for file I/O. handle is immutable.
	handle handle `state:"nosave"`

	// isRegularFile is true if this FD represents a regular file which is only
	// possible when filesystemOptions.regularFilesUseSpecialFileFD is in
	// effect. isRegularFile is immutable.
	isRegularFile bool

	// seekable is true if this file description represents a file for which
	// file offset is significant, i.e. a regular file, character device or
	// block device. seekable is immutable.
	seekable bool

	// haveQueue is true if this file description represents a file for which
	// queue may send I/O readiness events. haveQueue is immutable.
	haveQueue bool `state:"nosave"`
	queue     waiter.Queue

	// If seekable is true, off is the file offset. off is protected by mu.
	mu  sync.Mutex `state:"nosave"`
	off int64

	// If haveBuf is non-zero, this FD represents a pipe, and buf contains data
	// read from the pipe from previous calls to specialFileFD.savePipeData().
	// haveBuf and buf are protected by bufMu. haveBuf is accessed using atomic
	// memory operations.
	bufMu   sync.Mutex `state:"nosave"`
	haveBuf uint32
	buf     []byte

	// If handle.fd >= 0, hostFileMapper caches mappings of handle.fd, and
	// hostFileMapperInitOnce is used to initialize it on first use.
	hostFileMapperInitOnce sync.Once `state:"nosave"`
	hostFileMapper         fsutil.HostFileMapper

	// If handle.fd >= 0, fileRefs counts references on memmap.File offsets.
	// fileRefs is protected by fileRefsMu.
	fileRefsMu sync.Mutex `state:"nosave"`
	fileRefs   fsutil.FrameRefSet
}

func newSpecialFileFD(h handle, mnt *vfs.Mount, d *dentry, flags uint32) (*specialFileFD, error) {
	ftype := d.fileType()
	seekable := ftype == linux.S_IFREG || ftype == linux.S_IFCHR || ftype == linux.S_IFBLK
	haveQueue := (ftype == linux.S_IFIFO || ftype == linux.S_IFSOCK) && h.fd >= 0
	fd := &specialFileFD{
		handle:        h,
		isRegularFile: ftype == linux.S_IFREG,
		seekable:      seekable,
		haveQueue:     haveQueue,
	}
	fd.LockFD.Init(&d.locks)
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
	d.fs.syncMu.Lock()
	d.fs.specialFileFDs[fd] = struct{}{}
	d.fs.syncMu.Unlock()
	if fd.vfsfd.IsWritable() && (atomic.LoadUint32(&d.mode)&0111 != 0) {
		metric.SuspiciousOperationsMetric.Increment("opened_write_execute_file")
	}
	if h.fd >= 0 {
		fsmetric.GoferOpensHost.Increment()
	} else {
		fsmetric.GoferOpens9P.Increment()
	}
	return fd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *specialFileFD) Release(ctx context.Context) {
	if fd.haveQueue {
		fdnotifier.RemoveFD(fd.handle.fd)
	}
	fd.releaseMu.Lock()
	fd.handle.close(ctx)
	fd.releaseMu.Unlock()

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
	if fs := fd.filesystem(); fs.opts.lisaEnabled {
		return fd.handle.fdLisa.Flush(ctx)
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
func (fd *specialFileFD) EventRegister(e *waiter.Entry) error {
	if fd.haveQueue {
		fd.queue.EventRegister(e)
		if err := fdnotifier.UpdateFD(fd.handle.fd); err != nil {
			fd.queue.EventUnregister(e)
			return err
		}
		return nil
	}
	return fd.fileDescription.EventRegister(e)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *specialFileFD) EventUnregister(e *waiter.Entry) {
	if fd.haveQueue {
		fd.queue.EventUnregister(e)
		if err := fdnotifier.UpdateFD(fd.handle.fd); err != nil {
			panic(fmt.Sprint("UpdateFD:", err))
		}
		return
	}
	fd.fileDescription.EventUnregister(e)
}

func (fd *specialFileFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	if fd.isRegularFile {
		d := fd.dentry()
		return d.doAllocate(ctx, offset, length, func() error {
			if d.fs.opts.lisaEnabled {
				return fd.handle.fdLisa.Allocate(ctx, mode, offset, length)
			}
			return fd.handle.file.allocate(ctx, p9.ToAllocateMode(mode), offset, length)
		})
	}
	return fd.FileDescriptionDefaultImpl.Allocate(ctx, mode, offset, length)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *specialFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	start := fsmetric.StartReadWait()
	defer func() {
		if fd.handle.fd >= 0 {
			fsmetric.GoferReadsHost.Increment()
			fsmetric.FinishReadWait(fsmetric.GoferReadWaitHost, start)
		} else {
			fsmetric.GoferReads9P.Increment()
			fsmetric.FinishReadWait(fsmetric.GoferReadWait9P, start)
		}
	}()

	if fd.seekable && offset < 0 {
		return 0, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	if d := fd.dentry(); d.cachedMetadataAuthoritative() {
		d.touchAtime(fd.vfsfd.Mount())
	}

	bufN := int64(0)
	if atomic.LoadUint32(&fd.haveBuf) != 0 {
		var err error
		fd.bufMu.Lock()
		if len(fd.buf) != 0 {
			var n int
			n, err = dst.CopyOut(ctx, fd.buf)
			dst = dst.DropFirst(n)
			fd.buf = fd.buf[n:]
			if len(fd.buf) == 0 {
				atomic.StoreUint32(&fd.haveBuf, 0)
				fd.buf = nil
			}
			bufN = int64(n)
			if offset >= 0 {
				offset += bufN
			}
		}
		fd.bufMu.Unlock()
		if err != nil {
			return bufN, err
		}
	}

	rw := getHandleReadWriter(ctx, &fd.handle, offset)
	n, err := dst.CopyOutFrom(ctx, rw)
	putHandleReadWriter(rw)
	if linuxerr.Equals(linuxerr.EAGAIN, err) {
		err = linuxerr.ErrWouldBlock
	}
	return bufN + n, err
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
		return 0, offset, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select pwritev2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, linuxerr.EOPNOTSUPP
	}

	d := fd.dentry()
	if fd.isRegularFile {
		// If the regular file fd was opened with O_APPEND, make sure the file
		// size is updated. There is a possible race here if size is modified
		// externally after metadata cache is updated.
		if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 && !d.cachedMetadataAuthoritative() {
			if err := d.updateFromGetattr(ctx); err != nil {
				return 0, offset, err
			}
		}

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

	if d.cachedMetadataAuthoritative() {
		if fd.isRegularFile {
			d.touchCMtimeLocked()
		} else {
			d.touchCMtime()
		}
	}

	rw := getHandleReadWriter(ctx, &fd.handle, offset)
	n, err := src.CopyInTo(ctx, rw)
	putHandleReadWriter(rw)
	if linuxerr.Equals(linuxerr.EAGAIN, err) {
		err = linuxerr.ErrWouldBlock
	}
	// Update offset if the offset is valid.
	if offset >= 0 {
		offset += n
	}
	// Update file size for regular files.
	if fd.isRegularFile {
		// d.metadataMu is already locked at this point.
		if uint64(offset) > d.size {
			d.dataMu.Lock()
			defer d.dataMu.Unlock()
			atomic.StoreUint64(&d.size, uint64(offset))
		}
	}
	return int64(n), offset, err
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
		return 0, linuxerr.ESPIPE
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
	return fd.sync(ctx, false /* forFilesystemSync */, nil /* accFsyncFDIDsLisa */)
}

func (fd *specialFileFD) sync(ctx context.Context, forFilesystemSync bool, accFsyncFDIDsLisa *[]lisafs.FDID) error {
	// Locks to ensure it didn't race with fd.Release().
	fd.releaseMu.RLock()
	defer fd.releaseMu.RUnlock()

	if !fd.handle.isOpen() {
		return nil
	}
	err := func() error {
		// If we have a host FD, fsyncing it is likely to be faster than an fsync
		// RPC.
		if fd.handle.fd >= 0 {
			ctx.UninterruptibleSleepStart(false)
			err := unix.Fsync(int(fd.handle.fd))
			ctx.UninterruptibleSleepFinish(false)
			return err
		}
		if fs := fd.filesystem(); fs.opts.lisaEnabled {
			if accFsyncFDIDsLisa != nil {
				*accFsyncFDIDsLisa = append(*accFsyncFDIDsLisa, fd.handle.fdLisa.ID())
				return nil
			}
			return fd.handle.fdLisa.Sync(ctx)
		}
		return fd.handle.file.fsync(ctx)
	}()
	if err != nil {
		if !forFilesystemSync {
			return err
		}
		// Only return err if we can reasonably have expected sync to succeed
		// (fd represents a regular file that was opened for writing).
		if fd.isRegularFile && fd.vfsfd.IsWritable() {
			return err
		}
		ctx.Debugf("gofer.specialFileFD.sync: syncing non-writable or non-regular-file FD failed: %v", err)
	}
	return nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *specialFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if fd.handle.fd < 0 || fd.filesystem().opts.forcePageCache {
		return linuxerr.ENODEV
	}
	// After this point, fd may be used as a memmap.Mappable and memmap.File.
	fd.hostFileMapperInitOnce.Do(fd.hostFileMapper.Init)
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd, opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (fd *specialFileFD) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	fd.hostFileMapper.IncRefOn(memmap.MappableRange{offset, offset + uint64(ar.Length())})
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (fd *specialFileFD) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	fd.hostFileMapper.DecRefOn(memmap.MappableRange{offset, offset + uint64(ar.Length())})
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (fd *specialFileFD) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return fd.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (fd *specialFileFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	mr := optional
	if fd.filesystem().opts.limitHostFDTranslation {
		mr = maxFillRange(required, optional)
	}
	return []memmap.Translation{
		{
			Source: mr,
			File:   fd,
			Offset: mr.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (fd *specialFileFD) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// IncRef implements memmap.File.IncRef.
func (fd *specialFileFD) IncRef(fr memmap.FileRange) {
	fd.fileRefsMu.Lock()
	defer fd.fileRefsMu.Unlock()
	fd.fileRefs.IncRefAndAccount(fr)
}

// DecRef implements memmap.File.DecRef.
func (fd *specialFileFD) DecRef(fr memmap.FileRange) {
	fd.fileRefsMu.Lock()
	defer fd.fileRefsMu.Unlock()
	fd.fileRefs.DecRefAndAccount(fr)
}

// MapInternal implements memmap.File.MapInternal.
func (fd *specialFileFD) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	fd.requireHostFD()
	return fd.hostFileMapper.MapInternal(fr, int(fd.handle.fd), at.Write)
}

// FD implements memmap.File.FD.
func (fd *specialFileFD) FD() int {
	fd.requireHostFD()
	return int(fd.handle.fd)
}

func (fd *specialFileFD) requireHostFD() {
	if fd.handle.fd < 0 {
		// This is possible if fd was successfully mmapped before saving, then
		// was restored without a host FD. This is unrecoverable: without a
		// host FD, we can't mmap this file post-restore.
		panic("gofer.specialFileFD can no longer be memory-mapped without a host FD")
	}
}
