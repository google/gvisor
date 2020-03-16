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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// specialFileFD implements vfs.FileDescriptionImpl for files other than
// regular files, directories, and symlinks: pipes, sockets, etc. It is also
// used for regular files when filesystemOptions.specialRegularFiles is in
// effect. specialFileFD differs from regularFileFD by using per-FD handles
// instead of shared per-dentry handles, and never buffering I/O.
type specialFileFD struct {
	fileDescription

	// handle is immutable.
	handle handle

	// off is the file offset. off is protected by mu. (POSIX 2.9.7 only
	// requires operations using the file offset to be atomic for regular files
	// and symlinks; however, since specialFileFD may be used for regular
	// files, we apply this atomicity unconditionally.)
	mu  sync.Mutex
	off int64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *specialFileFD) Release() {
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

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *specialFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	// Going through dst.CopyOutFrom() holds MM locks around file operations of
	// unknown duration. For regularFileFD, doing so is necessary to support
	// mmap due to lock ordering; MM locks precede dentry.dataMu. That doesn't
	// hold here since specialFileFD doesn't client-cache data. Just buffer the
	// read instead.
	if d := fd.dentry(); d.fs.opts.interop != InteropModeShared {
		d.touchAtime(ctx, fd.vfsfd.Mount())
	}
	buf := make([]byte, dst.NumBytes())
	n, err := fd.handle.readToBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), uint64(offset))
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
	fd.mu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *specialFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	if fd.dentry().fileType() == linux.S_IFREG {
		limit, err := vfs.CheckLimit(ctx, offset, src.NumBytes())
		if err != nil {
			return 0, err
		}
		src = src.TakeFirst64(limit)
	}

	// Do a buffered write. See rationale in PRead.
	if d := fd.dentry(); d.fs.opts.interop != InteropModeShared {
		d.touchCMtime(ctx)
	}
	buf := make([]byte, src.NumBytes())
	// Don't do partial writes if we get a partial read from src.
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	n, err := fd.handle.writeFromBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), uint64(offset))
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *specialFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.PWrite(ctx, src, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *specialFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	default:
		// SEEK_END, SEEK_DATA, and SEEK_HOLE aren't supported since it's not
		// clear that file size is even meaningful for these files.
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *specialFileFD) Sync(ctx context.Context) error {
	if !fd.vfsfd.IsWritable() {
		return nil
	}
	return fd.handle.sync(ctx)
}
