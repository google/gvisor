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

package hostfd

import (
	"io"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
)

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
		iovs := safemem.IovecsFromBlockSeq(dsts)
		if len(iovs) > maxIov {
			log.Debugf("hostfd.Preadv2: truncating from %d iovecs to %d", len(iovs), maxIov)
			iovs = iovs[:maxIov]
		}
		n, _, e = unix.Syscall6(unix.SYS_PREADV2, uintptr(fd), uintptr((unsafe.Pointer)(&iovs[0])), uintptr(len(iovs)), uintptr(offset), 0 /* pos_h */, uintptr(flags))
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
		iovs := safemem.IovecsFromBlockSeq(srcs)
		if len(iovs) > maxIov {
			log.Debugf("hostfd.Preadv2: truncating from %d iovecs to %d", len(iovs), maxIov)
			iovs = iovs[:maxIov]
		}
		n, _, e = unix.Syscall6(unix.SYS_PWRITEV2, uintptr(fd), uintptr((unsafe.Pointer)(&iovs[0])), uintptr(len(iovs)), uintptr(offset), 0 /* pos_h */, uintptr(flags))
	}
	if e != 0 {
		return 0, e
	}
	return uint64(n), nil
}
