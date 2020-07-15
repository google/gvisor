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
	"sync"

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

	rw := getRegularFdReadWriter(ctx, fd, uint32(dst.NumBytes()), offset)

	if fd.vfsfd.StatusFlags()&linux.O_DIRECT != 0 {
		// Require the read to go to the remote file.
		rw.direct = true
	}

	rw.read()
	n, err := dst.CopyOutFrom(ctx, rw)
	putRegularFdReadWriter(rw)

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

type regularFdReadWriter struct {
	ctx    context.Context
	fd     *regularFileFD
	off    uint64
	direct bool

	// buffer for bytes read,
	// it should share the same array with the slice in FUSE response.
	buf []byte
	// actual bytes to read.
	size uint32
	// actual bytes read.
	n uint32
	// read error.
	err error
}

func (rw *regularFdReadWriter) fs() *filesystem {
	return rw.fd.inode().fs
}

var regularFdReadWriterPool = sync.Pool{
	New: func() interface{} {
		return &regularFdReadWriter{}
	},
}

func getRegularFdReadWriter(ctx context.Context, fd *regularFileFD, size uint32, offset int64) *regularFdReadWriter {
	rw := regularFdReadWriterPool.Get().(*regularFdReadWriter)
	rw.ctx = ctx
	rw.fd = fd
	rw.size = size
	rw.off = uint64(offset)
	// TODO(gvisor.dev/issue/3237): support indirect IO (e.g. caching)
	rw.direct = true
	return rw
}

func putRegularFdReadWriter(rw *regularFdReadWriter) {
	rw.ctx = nil
	rw.fd = nil
	rw.buf = nil
	regularFdReadWriterPool.Put(rw)
}

// issue the actual FUSE read request.
// See ReadToBlocks() on its existence.
func (rw *regularFdReadWriter) read() {
	// Send the FUSE_READ request and store the data in rw.
	rw.buf, rw.n, rw.err = rw.fs().Read(rw.ctx, rw.fd, rw.off, rw.size)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
// Due to a deadlock (both the caller of ReadToBlocks and the kernelTask.Block()
// will try to acquire the same lock), have to separate the rw.read() from the
// ReadToBlocks() function.
func (rw *regularFdReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
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

	if cp, cperr := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(rw.buf[:size]))); cperr != nil {
		return cp, cperr
	}

	return uint64(size), rw.err
}
