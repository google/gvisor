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
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/safemem"
)

// Preconditions: !dsts.IsEmpty().
func hostPreadv(fd int32, dsts safemem.BlockSeq, off int64) (uint64, error) {
	// No buffering is necessary regardless of safecopy; host syscalls will
	// return EFAULT if appropriate, instead of raising SIGBUS.
	if dsts.NumBlocks() == 1 {
		// Use pread() instead of preadv() to avoid iovec allocation and
		// copying.
		dst := dsts.Head()
		n, _, e := syscall.Syscall6(syscall.SYS_PREAD64, uintptr(fd), dst.Addr(), uintptr(dst.Len()), uintptr(off), 0, 0)
		if e != 0 {
			return 0, e
		}
		return uint64(n), nil
	}
	iovs := safemem.IovecsFromBlockSeq(dsts)
	n, _, e := syscall.Syscall6(syscall.SYS_PREADV, uintptr(fd), uintptr((unsafe.Pointer)(&iovs[0])), uintptr(len(iovs)), uintptr(off), 0, 0)
	if e != 0 {
		return 0, e
	}
	return uint64(n), nil
}

// Preconditions: !srcs.IsEmpty().
func hostPwritev(fd int32, srcs safemem.BlockSeq, off int64) (uint64, error) {
	// No buffering is necessary regardless of safecopy; host syscalls will
	// return EFAULT if appropriate, instead of raising SIGBUS.
	if srcs.NumBlocks() == 1 {
		// Use pwrite() instead of pwritev() to avoid iovec allocation and
		// copying.
		src := srcs.Head()
		n, _, e := syscall.Syscall6(syscall.SYS_PWRITE64, uintptr(fd), src.Addr(), uintptr(src.Len()), uintptr(off), 0, 0)
		if e != 0 {
			return 0, e
		}
		return uint64(n), nil
	}
	iovs := safemem.IovecsFromBlockSeq(srcs)
	n, _, e := syscall.Syscall6(syscall.SYS_PWRITEV, uintptr(fd), uintptr((unsafe.Pointer)(&iovs[0])), uintptr(len(iovs)), uintptr(off), 0, 0)
	if e != 0 {
		return 0, e
	}
	return uint64(n), nil
}
