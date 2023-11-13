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

// Package hostfd provides efficient I/O with host file descriptors.
package hostfd

import (
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sync"
)

// ReadWriterAt implements safemem.Reader and safemem.Writer by reading from
// and writing to a host file descriptor respectively. ReadWriterAts should be
// obtained by calling GetReadWriterAt.
//
// Clients should usually prefer to use Preadv2 and Pwritev2 directly.
type ReadWriterAt struct {
	fd     int32
	offset int64
	flags  uint32
}

var rwpool = sync.Pool{
	New: func() any {
		return &ReadWriterAt{}
	},
}

// GetReadWriterAt returns a ReadWriterAt that reads from / writes to the given
// host file descriptor, starting at the given offset and using the given
// preadv2(2)/pwritev2(2) flags. If offset is -1, the host file descriptor's
// offset is used instead. Users are responsible for ensuring that fd remains
// valid for the lifetime of the returned ReadWriterAt, and must call
// PutReadWriterAt when it is no longer needed.
func GetReadWriterAt(fd int32, offset int64, flags uint32) *ReadWriterAt {
	rw := rwpool.Get().(*ReadWriterAt)
	*rw = ReadWriterAt{
		fd:     fd,
		offset: offset,
		flags:  flags,
	}
	return rw
}

// PutReadWriterAt releases a ReadWriterAt returned by a previous call to
// GetReadWriterAt that is no longer in use.
func PutReadWriterAt(rw *ReadWriterAt) {
	rwpool.Put(rw)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *ReadWriterAt) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}
	n, err := Preadv2(rw.fd, dsts, rw.offset, rw.flags)
	if rw.offset >= 0 {
		rw.offset += int64(n)
	}
	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *ReadWriterAt) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}
	n, err := Pwritev2(rw.fd, srcs, rw.offset, rw.flags)
	if rw.offset >= 0 {
		rw.offset += int64(n)
	}
	return n, err
}

// Preadv2 reads up to dsts.NumBytes() bytes from host file descriptor fd into
// dsts. offset and flags are interpreted as for preadv2(2).
//
// Preconditions: !dsts.IsEmpty().
func Preadv2(fd int32, dsts safemem.BlockSeq, offset int64, flags uint32) (uint64, error) {
	// No buffering is necessary regardless of safecopy; host syscalls will
	// return EFAULT if appropriate, instead of raising SIGBUS.
	var (
		n uintptr
		e unix.Errno
	)
	if flags == 0 && dsts.NumBlocks() == 1 {
		// Use read() or pread() to avoid iovec allocation and copying.
		dst := dsts.Head()
		if offset == -1 {
			n, _, e = unix.Syscall(unix.SYS_READ, uintptr(fd), dst.Addr(), uintptr(dst.Len()))
		} else {
			n, _, e = unix.Syscall6(unix.SYS_PREAD64, uintptr(fd), dst.Addr(), uintptr(dst.Len()), uintptr(offset), 0 /* pos_h */, 0 /* unused */)
		}
	} else {
		n, e = iovecsReadWrite(unix.SYS_PREADV2, fd, safemem.IovecsFromBlockSeq(dsts), offset, flags)
	}
	if e != 0 {
		return 0, e
	}
	if n == 0 {
		return 0, io.EOF
	}
	return uint64(n), nil
}

// Pwritev2 writes up to srcs.NumBytes() from srcs into host file descriptor
// fd. offset and flags are interpreted as for pwritev2(2).
//
// Preconditions: !srcs.IsEmpty().
func Pwritev2(fd int32, srcs safemem.BlockSeq, offset int64, flags uint32) (uint64, error) {
	// No buffering is necessary regardless of safecopy; host syscalls will
	// return EFAULT if appropriate, instead of raising SIGBUS.
	var (
		n uintptr
		e unix.Errno
	)
	if flags == 0 && srcs.NumBlocks() == 1 {
		// Use write() or pwrite() to avoid iovec allocation and copying.
		src := srcs.Head()
		if offset == -1 {
			n, _, e = unix.Syscall(unix.SYS_WRITE, uintptr(fd), src.Addr(), uintptr(src.Len()))
		} else {
			n, _, e = unix.Syscall6(unix.SYS_PWRITE64, uintptr(fd), src.Addr(), uintptr(src.Len()), uintptr(offset), 0 /* pos_h */, 0 /* unused */)
		}
	} else {
		n, e = iovecsReadWrite(unix.SYS_PWRITEV2, fd, safemem.IovecsFromBlockSeq(srcs), offset, flags)
	}
	if e != 0 {
		return 0, e
	}
	return uint64(n), nil
}
