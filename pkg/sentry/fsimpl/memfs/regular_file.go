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

package memfs

import (
	"io"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

type regularFile struct {
	inode inode

	mu   sync.RWMutex
	data []byte
	// dataLen is len(data), but accessed using atomic memory operations to
	// avoid locking in inode.stat().
	dataLen int64
}

func (fs *filesystem) newRegularFile(creds *auth.Credentials, mode uint16) *inode {
	file := &regularFile{}
	file.inode.init(file, fs, creds, mode)
	file.inode.nlink = 1 // from parent directory
	return &file.inode
}

type regularFileFD struct {
	fileDescription
	vfs.FileDescriptionDefaultImpl

	// These are immutable.
	readable bool
	writable bool

	// off is the file offset. off is accessed using atomic memory operations.
	// offMu serializes operations that may mutate off.
	off   int64
	offMu sync.Mutex
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release() {
	if fd.writable {
		fd.vfsfd.VirtualDentry().Mount().EndWrite()
	}
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if !fd.readable {
		return 0, syserror.EINVAL
	}
	f := fd.inode().impl.(*regularFile)
	f.mu.RLock()
	if offset >= int64(len(f.data)) {
		f.mu.RUnlock()
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, f.data[offset:])
	f.mu.RUnlock()
	return int64(n), err
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
	if !fd.writable {
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	srclen := src.NumBytes()
	if srclen == 0 {
		return 0, nil
	}
	f := fd.inode().impl.(*regularFile)
	f.mu.Lock()
	end := offset + srclen
	if end < offset {
		// Overflow.
		f.mu.Unlock()
		return 0, syserror.EFBIG
	}
	if end > f.dataLen {
		f.data = append(f.data, make([]byte, end-f.dataLen)...)
		atomic.StoreInt64(&f.dataLen, end)
	}
	n, err := src.CopyIn(ctx, f.data[offset:end])
	f.mu.Unlock()
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PWrite(ctx, src, fd.off, opts)
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.offMu.Lock()
	defer fd.offMu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// use offset as specified
	case linux.SEEK_CUR:
		offset += fd.off
	case linux.SEEK_END:
		offset += atomic.LoadInt64(&fd.inode().impl.(*regularFile).dataLen)
	default:
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *regularFileFD) Sync(ctx context.Context) error {
	return nil
}
