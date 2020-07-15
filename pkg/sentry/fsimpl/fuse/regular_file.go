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

	size := dst.NumBytes()
	if size == 0 {
		// Early return if count is 0.
		return 0, nil
	} else if size > math.MaxUint32 {
		// FUSE only supports uint32 for size.
		// Overflow.
		return 0, syserror.EINVAL
	}

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	inode := fd.inode()

	// Reading beyond EOF, update file size if outdated.
	if uint64(offset+size) > atomic.LoadUint64(&inode.size) {
		if err := inode.reviseAttr(ctx); err != nil {
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
			return 0, syserror.EIO
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
