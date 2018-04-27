// Copyright 2018 Google Inc.
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

package host

import (
	"syscall"
	"unsafe"
)

// buildIovec builds an iovec slice from the given []byte slice.
func buildIovec(bufs [][]byte) (uintptr, []syscall.Iovec) {
	var length uintptr
	iovecs := make([]syscall.Iovec, 0, 10)
	for i := range bufs {
		if l := len(bufs[i]); l > 0 {
			length += uintptr(l)
			iovecs = append(iovecs, syscall.Iovec{
				Base: &bufs[i][0],
				Len:  uint64(l),
			})
		}
	}
	return length, iovecs
}

func fdReadVec(fd int, bufs [][]byte, control []byte, peek bool) (readLen uintptr, msgLen uintptr, controlLen uint64, err error) {
	flags := uintptr(syscall.MSG_DONTWAIT | syscall.MSG_TRUNC)
	if peek {
		flags |= syscall.MSG_PEEK
	}

	length, iovecs := buildIovec(bufs)

	var msg syscall.Msghdr
	if len(control) != 0 {
		msg.Control = &control[0]
		msg.Controllen = uint64(len(control))
	}

	if len(iovecs) != 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}
	n, _, e := syscall.RawSyscall(syscall.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), flags)
	if e != 0 {
		return 0, 0, 0, e
	}

	if n > length {
		return length, n, msg.Controllen, nil
	}

	return n, n, msg.Controllen, nil
}

func fdWriteVec(fd int, bufs [][]byte) (uintptr, error) {
	_, iovecs := buildIovec(bufs)

	var msg syscall.Msghdr
	if len(iovecs) > 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}
	n, _, e := syscall.RawSyscall(syscall.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
	if e != 0 {
		return 0, e
	}

	return n, nil
}
