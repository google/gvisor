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
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sizeofIovec  = unsafe.Sizeof(unix.Iovec{})
	sizeofMsghdr = unsafe.Sizeof(unix.Msghdr{})
)

func iovecsReadWrite(sysno uintptr, fd int32, iovs []unix.Iovec, offset int64, flags uint32) (uintptr, unix.Errno) {
	var total uintptr
	for start := 0; start < len(iovs); start += MaxReadWriteIov {
		last := true
		size := len(iovs) - start
		if size > MaxReadWriteIov {
			last = false
			size = MaxReadWriteIov
		}
		curOff := offset
		if offset >= 0 {
			curOff = offset + int64(total)
		}
		cur, _, e := unix.Syscall6(sysno, uintptr(fd), uintptr((unsafe.Pointer)(&iovs[start])), uintptr(size), uintptr(curOff), 0 /* pos_h */, uintptr(flags))
		if cur > 0 {
			total += cur
		}
		if e != 0 {
			return total, e
		}
		if last {
			break
		}
		// If this was a short read/write, then break.
		var curTotal uint64
		for i := range iovs[start : start+size] {
			curTotal += iovs[i].Len
		}
		if uint64(cur) < curTotal {
			break
		}
	}
	return total, 0
}
