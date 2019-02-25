// Copyright 2018 Google LLC
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

package unet

import (
	"io"
	"math"
	"sync/atomic"
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// wait blocks until the socket FD is ready for reading or writing, depending
// on the value of write.
//
// Returns errClosing if the Socket is in the process of closing.
func (s *Socket) wait(write bool) error {
	for {
		// Checking the FD on each loop is not strictly necessary, it
		// just avoids an extra poll call.
		fd := atomic.LoadInt32(&s.fd)
		if fd < 0 {
			return errClosing
		}

		events := []linux.PollFD{
			{
				// The actual socket FD.
				FD:     fd,
				Events: linux.POLLIN,
			},
			{
				// The eventfd, signaled when we are closing.
				FD:     int32(s.efd),
				Events: linux.POLLIN,
			},
		}
		if write {
			events[0].Events = linux.POLLOUT
		}

		_, _, e := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(&events[0])), 2, uintptr(math.MaxUint64))
		if e == syscall.EINTR {
			continue
		}
		if e != 0 {
			return e
		}

		if events[1].REvents&linux.POLLIN == linux.POLLIN {
			// eventfd signaled, we're closing.
			return errClosing
		}

		return nil
	}
}

// buildIovec builds an iovec slice from the given []byte slice.
//
// iovecs is used as an initial slice, to avoid excessive allocations.
func buildIovec(bufs [][]byte, iovecs []syscall.Iovec) ([]syscall.Iovec, int) {
	var length int
	for i := range bufs {
		if l := len(bufs[i]); l > 0 {
			iovecs = append(iovecs, syscall.Iovec{
				Base: &bufs[i][0],
				Len:  uint64(l),
			})
			length += l
		}
	}
	return iovecs, length
}

// ReadVec reads into the pre-allocated bufs. Returns bytes read.
//
// The pre-allocatted space used by ReadVec is based upon slice lengths.
//
// This function is not guaranteed to read all available data, it
// returns as soon as a single recvmsg call succeeds.
func (r *SocketReader) ReadVec(bufs [][]byte) (int, error) {
	iovecs, length := buildIovec(bufs, make([]syscall.Iovec, 0, 2))

	var msg syscall.Msghdr
	if len(r.source) != 0 {
		msg.Name = &r.source[0]
		msg.Namelen = uint32(len(r.source))
	}

	if len(r.ControlMessage) != 0 {
		msg.Control = &r.ControlMessage[0]
		msg.Controllen = uint64(len(r.ControlMessage))
	}

	if len(iovecs) != 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}

	// n is the bytes received.
	var n uintptr

	fd, ok := r.socket.enterFD()
	if !ok {
		return 0, syscall.EBADF
	}
	// Leave on returns below.
	for {
		var e syscall.Errno

		// Try a non-blocking recv first, so we don't give up the go runtime M.
		n, _, e = syscall.RawSyscall(syscall.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), syscall.MSG_DONTWAIT|syscall.MSG_TRUNC)
		if e == 0 {
			break
		}
		if e == syscall.EINTR {
			continue
		}
		if !r.blocking {
			r.socket.gate.Leave()
			return 0, e
		}
		if e != syscall.EAGAIN && e != syscall.EWOULDBLOCK {
			r.socket.gate.Leave()
			return 0, e
		}

		// Wait for the socket to become readable.
		err := r.socket.wait(false)
		if err == errClosing {
			err = syscall.EBADF
		}
		if err != nil {
			r.socket.gate.Leave()
			return 0, err
		}
	}

	r.socket.gate.Leave()

	if msg.Controllen < uint64(len(r.ControlMessage)) {
		r.ControlMessage = r.ControlMessage[:msg.Controllen]
	}

	if msg.Namelen < uint32(len(r.source)) {
		r.source = r.source[:msg.Namelen]
	}

	// All unet sockets are SOCK_STREAM or SOCK_SEQPACKET, both of which
	// indicate that the other end is closed by returning a 0 length read
	// with no error.
	if n == 0 {
		return 0, io.EOF
	}

	if r.race != nil {
		// See comments on Socket.race.
		atomic.AddInt32(r.race, 1)
	}

	if int(n) > length {
		return length, errMessageTruncated
	}

	return int(n), nil
}

// WriteVec writes the bufs to the socket. Returns bytes written.
//
// This function is not guaranteed to send all data, it returns
// as soon as a single sendmsg call succeeds.
func (w *SocketWriter) WriteVec(bufs [][]byte) (int, error) {
	iovecs, _ := buildIovec(bufs, make([]syscall.Iovec, 0, 2))

	if w.race != nil {
		// See comments on Socket.race.
		atomic.AddInt32(w.race, 1)
	}

	var msg syscall.Msghdr
	if len(w.to) != 0 {
		msg.Name = &w.to[0]
		msg.Namelen = uint32(len(w.to))
	}

	if len(w.ControlMessage) != 0 {
		msg.Control = &w.ControlMessage[0]
		msg.Controllen = uint64(len(w.ControlMessage))
	}

	if len(iovecs) > 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}

	fd, ok := w.socket.enterFD()
	if !ok {
		return 0, syscall.EBADF
	}
	// Leave on returns below.
	for {
		// Try a non-blocking send first, so we don't give up the go runtime M.
		n, _, e := syscall.RawSyscall(syscall.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
		if e == 0 {
			w.socket.gate.Leave()
			return int(n), nil
		}
		if e == syscall.EINTR {
			continue
		}
		if !w.blocking {
			w.socket.gate.Leave()
			return 0, e
		}
		if e != syscall.EAGAIN && e != syscall.EWOULDBLOCK {
			w.socket.gate.Leave()
			return 0, e
		}

		// Wait for the socket to become writeable.
		err := w.socket.wait(true)
		if err == errClosing {
			err = syscall.EBADF
		}
		if err != nil {
			w.socket.gate.Leave()
			return 0, err
		}
	}
	// Unreachable, no s.gate.Leave needed.
}

// getsockopt issues a getsockopt syscall.
func getsockopt(fd int, level int, optname int, buf []byte) (uint32, error) {
	l := uint32(len(buf))
	_, _, e := syscall.RawSyscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 {
		return 0, e
	}

	return l, nil
}

// setsockopt issues a setsockopt syscall.
func setsockopt(fd int, level int, optname int, buf []byte) error {
	_, _, e := syscall.RawSyscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if e != 0 {
		return e
	}

	return nil
}

// getsockname issues a getsockname syscall.
func getsockname(fd int, buf []byte) (uint32, error) {
	l := uint32(len(buf))
	_, _, e := syscall.RawSyscall(syscall.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)))
	if e != 0 {
		return 0, e
	}

	return l, nil
}

// getpeername issues a getpeername syscall.
func getpeername(fd int, buf []byte) (uint32, error) {
	l := uint32(len(buf))
	_, _, e := syscall.RawSyscall(syscall.SYS_GETPEERNAME, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)))
	if e != 0 {
		return 0, e
	}

	return l, nil
}
