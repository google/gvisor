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
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

type regularFileFD struct {
	fileDescription

	// off is the file offset.
	off int64
	// offMu protects off.
	offMu sync.Mutex
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	size := uint32(dst.NumBytes())
	if size == 0 {
		return 0, nil
	}

	rw := getRegularFDReadWriter(ctx, fd, size, offset)

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	rw.read()
	n, err := dst.CopyOutFrom(ctx, rw)

	putRegularFDReadWriter(rw)

	return n, err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

type regularFDReadWriter struct {
	ctx context.Context
	fd  *regularFileFD

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	// bytes to read.
	size uint32
	// offset of read.
	off uint64

	// actual bytes read.
	n uint32
	// read error.
	err error

	// buffer for bytes read,
	// ideally it shares the same array with the slice in FUSE response
	// for the reads that can fit in one FUSE_READ request.
	buf []byte
}

func (rw *regularFDReadWriter) fs() *filesystem {
	return rw.fd.inode().fs
}

var regularFdReadWriterPool = sync.Pool{
	New: func() interface{} {
		return &regularFDReadWriter{}
	},
}

func getRegularFDReadWriter(ctx context.Context, fd *regularFileFD, size uint32, offset int64) *regularFDReadWriter {
	rw := regularFdReadWriterPool.Get().(*regularFDReadWriter)
	rw.ctx = ctx
	rw.fd = fd
	rw.size = size
	rw.off = uint64(offset)
	return rw
}

func putRegularFDReadWriter(rw *regularFDReadWriter) {
	rw.ctx = nil
	rw.fd = nil
	rw.buf = nil
	rw.n = 0
	rw.err = nil
	regularFdReadWriterPool.Put(rw)
}

// read handles and issues the actual FUSE read request.
// See ReadToBlocks() regarding its purpose.
func (rw *regularFDReadWriter) read() {
	// TODO(gvisor.dev/issue/3237): support indirect IO (e.g. caching):
	// use caching when possible.

	inode := rw.fd.inode()

	// Reading beyond EOF, update file size if outdated.
	if rw.off+uint64(rw.size) >= atomic.LoadUint64(&inode.size) {
		if err := inode.reviseAttr(rw.ctx); err != nil {
			rw.err = err
			return
		}
		// If the offset after update is still too large, return error.
		if rw.off >= atomic.LoadUint64(&inode.size) {
			rw.err = io.EOF
			return
		}
	}

	// Truncate the read with updated file size.
	fileSize := atomic.LoadUint64(&inode.size)
	if rw.off+uint64(rw.size) > fileSize {
		// This uint32 conversion will not overflow.
		// Since rw.off < fileSize and the difference
		// between must be less than rw.size to make
		// the if condition true.
		rw.size = uint32(fileSize - rw.off)
	}

	// Send the FUSE_READ request and store the data in rw.
	rw.buf, rw.n, rw.err = rw.fs().ReadInPages(rw.ctx, rw.fd, rw.off, rw.size)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
// Due to a deadlock (both the caller of ReadToBlocks and the kernelTask.Block()
// will try to acquire the same lock), have to separate the rw.read() from the
// ReadToBlocks() function. Therefore, ReadToBlocks() only handles copying
// the result into user memory while read() handles the actual reading.
func (rw *regularFDReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if rw.err != nil {
		return 0, rw.err
	}

	if dsts.IsEmpty() {
		return 0, nil
	}

	// TODO(gvisor.dev/issue/3237): support indirect IO (e.g. caching),
	// store the bytes that were read ahead.

	// The actual number of bytes to copy.
	var size uint32
	if rw.size < rw.n {
		// Read more bytes: read ahead.
		// This is the common case since FUSE will round up the
		// size to read to a multiple of usermem.PageSize.
		size = rw.size
	} else {
		size = rw.n
	}

	// Assume rw.size is less or equal to dsts.NumBytes().
	if cp, cperr := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(rw.buf[:size]))); cperr != nil {
		return cp, cperr
	}

	return uint64(size), nil
}
