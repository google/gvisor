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

// +build linux

// Package rawfile contains utilities for using the netstack with raw host
// files on Linux hosts.
package rawfile

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// GetMTU determines the MTU of a network interface device.
func GetMTU(name string) (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

// NonBlockingWrite writes the given buffer to a file descriptor. It fails if
// partial data is written.
func NonBlockingWrite(fd int, buf []byte) *tcpip.Error {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	_, _, e := syscall.RawSyscall(syscall.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	if e != 0 {
		return TranslateErrno(e)
	}

	return nil
}

// NonBlockingWriteIovec writes iovec to a file descriptor in a single syscall.
// It fails if partial data is written.
func NonBlockingWriteIovec(fd int, iovec []syscall.Iovec) *tcpip.Error {
	iovecLen := uintptr(len(iovec))
	_, _, e := syscall.RawSyscall(syscall.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), iovecLen)
	if e != 0 {
		return TranslateErrno(e)
	}
	return nil
}

// NonBlockingSendMMsg sends multiple messages on a socket.
func NonBlockingSendMMsg(fd int, msgHdrs []MMsgHdr) (int, *tcpip.Error) {
	n, _, e := syscall.RawSyscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), syscall.MSG_DONTWAIT, 0, 0)
	if e != 0 {
		return 0, TranslateErrno(e)
	}

	return int(n), nil
}

// PollEvent represents the pollfd structure passed to a poll() system call.
type PollEvent struct {
	FD      int32
	Events  int16
	Revents int16
}

// BlockingRead reads from a file descriptor that is set up as non-blocking. If
// no data is available, it will block in a poll() syscall until the file
// descriptor becomes readable.
func BlockingRead(fd int, b []byte) (int, *tcpip.Error) {
	for {
		n, _, e := syscall.RawSyscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if e == 0 {
			return int(n), nil
		}

		event := PollEvent{
			FD:     int32(fd),
			Events: 1, // POLLIN
		}

		_, e = BlockingPoll(&event, 1, nil)
		if e != 0 && e != syscall.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}

// BlockingReadv reads from a file descriptor that is set up as non-blocking and
// stores the data in a list of iovecs buffers. If no data is available, it will
// block in a poll() syscall until the file descriptor becomes readable.
func BlockingReadv(fd int, iovecs []syscall.Iovec) (int, *tcpip.Error) {
	for {
		n, _, e := syscall.RawSyscall(syscall.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e == 0 {
			return int(n), nil
		}

		event := PollEvent{
			FD:     int32(fd),
			Events: 1, // POLLIN
		}

		_, e = BlockingPoll(&event, 1, nil)
		if e != 0 && e != syscall.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}

// MMsgHdr represents the mmsg_hdr structure required by recvmmsg() on linux.
type MMsgHdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

// BlockingRecvMMsg reads from a file descriptor that is set up as non-blocking
// and stores the received messages in a slice of MMsgHdr structures. If no data
// is available, it will block in a poll() syscall until the file descriptor
// becomes readable.
func BlockingRecvMMsg(fd int, msgHdrs []MMsgHdr) (int, *tcpip.Error) {
	for {
		n, _, e := syscall.RawSyscall6(syscall.SYS_RECVMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), syscall.MSG_DONTWAIT, 0, 0)
		if e == 0 {
			return int(n), nil
		}

		event := PollEvent{
			FD:     int32(fd),
			Events: 1, // POLLIN
		}

		if _, e := BlockingPoll(&event, 1, nil); e != 0 && e != syscall.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}
