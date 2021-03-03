// Copyright 2018 The gVisor Authors.
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
	"unsafe"

	"golang.org/x/sys/unix"
)

// LINT.IfChange

// fdReadVec receives from fd to bufs.
//
// If the total length of bufs is > maxlen, fdReadVec will do a partial read
// and err will indicate why the message was truncated.
func fdReadVec(fd int, bufs [][]byte, control []byte, peek bool, maxlen int64) (readLen int64, msgLen int64, controlLen uint64, controlTrunc bool, err error) {
	flags := uintptr(unix.MSG_DONTWAIT | unix.MSG_TRUNC)
	if peek {
		flags |= unix.MSG_PEEK
	}

	// Always truncate the receive buffer. All socket types will truncate
	// received messages.
	length, iovecs, intermediate, err := buildIovec(bufs, maxlen, true)
	if err != nil && len(iovecs) == 0 {
		// No partial write to do, return error immediately.
		return 0, 0, 0, false, err
	}

	var msg unix.Msghdr
	if len(control) != 0 {
		msg.Control = &control[0]
		msg.Controllen = uint64(len(control))
	}

	if len(iovecs) != 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}

	rawN, _, e := unix.RawSyscall(unix.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), flags)
	if e != 0 {
		// N.B. prioritize the syscall error over the buildIovec error.
		return 0, 0, 0, false, e
	}
	n := int64(rawN)

	// Copy data back to bufs.
	if intermediate != nil {
		copyToMulti(bufs, intermediate)
	}

	controlTrunc = msg.Flags&unix.MSG_CTRUNC == unix.MSG_CTRUNC

	if n > length {
		return length, n, msg.Controllen, controlTrunc, nil
	}

	return n, n, msg.Controllen, controlTrunc, nil
}

// fdWriteVec sends from bufs to fd.
//
// If the total length of bufs is > maxlen && truncate, fdWriteVec will do a
// partial write and err will indicate why the message was truncated.
func fdWriteVec(fd int, bufs [][]byte, maxlen int64, truncate bool) (int64, int64, error) {
	length, iovecs, intermediate, err := buildIovec(bufs, maxlen, truncate)
	if err != nil && len(iovecs) == 0 {
		// No partial write to do, return error immediately.
		return 0, length, err
	}

	// Copy data to intermediate buf.
	if intermediate != nil {
		copyFromMulti(intermediate, bufs)
	}

	var msg unix.Msghdr
	if len(iovecs) > 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}

	n, _, e := unix.RawSyscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if e != 0 {
		// N.B. prioritize the syscall error over the buildIovec error.
		return 0, length, e
	}

	return int64(n), length, err
}

// LINT.ThenChange(../../fsimpl/host/socket_unsafe.go)
