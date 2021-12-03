// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	"io"
	"math"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

type regularFileFD struct {
	fileDescription
	vfs.SpliceInFD

	// off is the file offset.
	off int64
	// offMu protects off.
	offMu sync.Mutex
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	size := dst.NumBytes()
	if size == 0 {
		// Early return if count is 0.
		return 0, nil
	} else if size > math.MaxUint32 {
		// FUSE only supports uint32 for size.
		// Overflow.
		return 0, linuxerr.EINVAL
	}

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	inode := fd.inode()

	// Reading beyond EOF, update file size if outdated.
	if uint64(offset+size) > atomic.LoadUint64(&inode.size) {
		if err := inode.reviseAttr(ctx, linux.FUSE_GETATTR_FH, fd.Fh); err != nil {
			return 0, err
		}
		// If the offset after update is still too large, return error.
		if uint64(offset) >= atomic.LoadUint64(&inode.size) {
			return 0, io.EOF
		}
	}

	// Truncate the read with updated file size.
	fileSize := atomic.LoadUint64(&inode.size)
	if uint64(offset+size) > fileSize {
		size = int64(fileSize) - offset
	}

	buffers, n, err := inode.fs.ReadInPages(ctx, fd, uint64(offset), uint32(size))
	if err != nil {
		return 0, err
	}

	// TODO(gvisor.dev/issue/3237): support indirect IO (e.g. caching),
	// store the bytes that were read ahead.

	// Update the number of bytes to copy for short read.
	if n < uint32(size) {
		size = int64(n)
	}

	// Copy the bytes read to the dst.
	// This loop is intended for fragmented reads.
	// For the majority of reads, this loop only execute once.
	var copied int64
	for _, buffer := range buffers {
		toCopy := int64(len(buffer))
		if copied+toCopy > size {
			toCopy = size - copied
		}
		cp, err := dst.DropFirst64(copied).CopyOut(ctx, buffer[:toCopy])
		if err != nil {
			return 0, err
		}
		if int64(cp) != toCopy {
			return 0, linuxerr.EIO
		}
		copied += toCopy
	}

	return copied, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.offMu.Lock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	fd.offMu.Unlock()
	return n, err
}

// pwrite returns the number of bytes written, final offset and error. The
// final offset should be ignored by PWrite.
func (fd *regularFileFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, linuxerr.EOPNOTSUPP
	}

	inode := fd.inode()
	inode.metadataMu.Lock()
	defer inode.metadataMu.Unlock()

	// If the file is opened with O_APPEND, update offset to file size.
	// Note: since our Open() implements the interface of kernfs,
	// and kernfs currently does not support O_APPEND, this will never
	// be true before we switch out from kernfs.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		// Locking inode.metadataMu is sufficient for reading size
		offset = int64(inode.size)
	}

	srclen := src.NumBytes()

	if srclen > math.MaxUint32 {
		// FUSE only supports uint32 for size.
		// Overflow.
		return 0, offset, linuxerr.EINVAL
	}
	if end := offset + srclen; end < offset {
		// Overflow.
		return 0, offset, linuxerr.EINVAL
	}

	srclen, err = vfs.CheckLimit(ctx, offset, srclen)
	if err != nil {
		return 0, offset, err
	}

	if srclen == 0 {
		// Return before causing any side effects.
		return 0, offset, nil
	}

	src = src.TakeFirst64(srclen)

	// TODO(gvisor.dev/issue/3237): Add cache support:
	// buffer cache. Ideally we write from src to our buffer cache first.
	// The slice passed to fs.Write() should be a slice from buffer cache.
	data := make([]byte, srclen)
	// Reason for making a copy here: connection.Call() blocks on kerneltask,
	// which in turn acquires mm.activeMu lock. Functions like CopyInTo() will
	// attemp to acquire the mm.activeMu lock as well -> deadlock.
	// We must finish reading from the userspace memory before
	// t.Block() deactivates it.
	cp, err := src.CopyIn(ctx, data)
	if err != nil {
		return 0, offset, err
	}
	if int64(cp) != srclen {
		return 0, offset, linuxerr.EIO
	}

	n, err := fd.inode().fs.Write(ctx, fd, uint64(offset), uint32(srclen), data)
	if err != nil {
		return 0, offset, err
	}

	if n == 0 {
		// We have checked srclen != 0 previously.
		// If err == nil, then it's a short write and we return EIO.
		return 0, offset, linuxerr.EIO
	}

	written = int64(n)
	finalOff = offset + written

	if finalOff > int64(inode.size) {
		atomic.StoreUint64(&inode.size, uint64(finalOff))
		atomic.AddUint64(&inode.fs.conn.attributeVersion, 1)
	}

	return
}
