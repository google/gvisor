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

//go:build linux
// +build linux

// Package rawfile contains utilities for using the netstack with raw host
// files on Linux hosts.
package rawfile

import (
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// SizeofIovec is the size of a unix.Iovec in bytes.
const SizeofIovec = unsafe.Sizeof(unix.Iovec{})

// MaxIovs is UIO_MAXIOV, the maximum number of iovecs that may be passed to a
// host system call in a single array.
const MaxIovs = 1024

// IovecFromBytes returns a unix.Iovec representing bs.
//
// Preconditions: len(bs) > 0.
func IovecFromBytes(bs []byte) unix.Iovec {
	iov := unix.Iovec{
		Base: &bs[0],
	}
	iov.SetLen(len(bs))
	return iov
}

func bytesFromIovec(iov unix.Iovec) (bs []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	sh.Data = uintptr(unsafe.Pointer(iov.Base))
	sh.Len = int(iov.Len)
	sh.Cap = int(iov.Len)
	return
}

// AppendIovecFromBytes returns append(iovs, IovecFromBytes(bs)). If len(bs) ==
// 0, AppendIovecFromBytes returns iovs without modification. If len(iovs) >=
// max, AppendIovecFromBytes replaces the final iovec in iovs with one that
// also includes the contents of bs. Note that this implies that
// AppendIovecFromBytes is only usable when the returned iovec slice is used as
// the source of a write.
func AppendIovecFromBytes(iovs []unix.Iovec, bs []byte, max int) []unix.Iovec {
	if len(bs) == 0 {
		return iovs
	}
	if len(iovs) < max {
		return append(iovs, IovecFromBytes(bs))
	}
	iovs[len(iovs)-1] = IovecFromBytes(append(bytesFromIovec(iovs[len(iovs)-1]), bs...))
	return iovs
}

// MMsgHdr represents the mmsg_hdr structure required by recvmmsg() on linux.
type MMsgHdr struct {
	Msg unix.Msghdr
	Len uint32
	_   [4]byte
}

// SizeofMMsgHdr is the size of a MMsgHdr in bytes.
const SizeofMMsgHdr = unsafe.Sizeof(MMsgHdr{})

// GetMTU determines the MTU of a network interface device.
func GetMTU(name string) (uint32, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

// NonBlockingWrite writes the given buffer to a file descriptor. It fails if
// partial data is written.
func NonBlockingWrite(fd int, buf []byte) tcpip.Error {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	_, _, e := unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	if e != 0 {
		return TranslateErrno(e)
	}

	return nil
}

// NonBlockingWriteIovec writes iovec to a file descriptor in a single unix.
// It fails if partial data is written.
func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) tcpip.Error {
	iovecLen := uintptr(len(iovec))
	_, _, e := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), iovecLen)
	if e != 0 {
		return TranslateErrno(e)
	}
	return nil
}

// NonBlockingSendMMsg sends multiple messages on a socket.
func NonBlockingSendMMsg(fd int, msgHdrs []MMsgHdr) (int, tcpip.Error) {
	n, _, e := unix.RawSyscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
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
func BlockingRead(fd int, b []byte) (int, tcpip.Error) {
	n, err := BlockingReadUntranslated(fd, b)
	if err != 0 {
		return n, TranslateErrno(err)
	}
	return n, nil
}

// BlockingReadUntranslated reads from a file descriptor that is set up as
// non-blocking. If no data is available, it will block in a poll() syscall
// until the file descriptor becomes readable. It returns the raw unix.Errno
// value returned by the underlying syscalls.
func BlockingReadUntranslated(fd int, b []byte) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if e == 0 {
			return int(n), 0
		}

		event := PollEvent{
			FD:     int32(fd),
			Events: 1, // POLLIN
		}

		_, e = BlockingPoll(&event, 1, nil)
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

// BlockingReadvUntilStopped reads from a file descriptor that is set up as
// non-blocking and stores the data in a list of iovecs buffers. If no data is
// available, it will block in a poll() syscall until the file descriptor
// becomes readable or stop is signalled (efd becomes readable). Returns -1 in
// the latter case.
func BlockingReadvUntilStopped(efd int, fd int, iovecs []unix.Iovec) (int, tcpip.Error) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e == 0 {
			return int(n), nil
		}
		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, TranslateErrno(e)
		}
		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, nil
		}
		if e != 0 && e != unix.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}

// BlockingRecvMMsgUntilStopped reads from a file descriptor that is set up as
// non-blocking and stores the received messages in a slice of MMsgHdr
// structures. If no data is available, it will block in a poll() syscall until
// the file descriptor becomes readable or stop is signalled (efd becomes
// readable). Returns -1 in the latter case.
func BlockingRecvMMsgUntilStopped(efd int, fd int, msgHdrs []MMsgHdr) (int, tcpip.Error) {
	for {
		n, _, e := unix.RawSyscall6(unix.SYS_RECVMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
		if e == 0 {
			return int(n), nil
		}

		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, TranslateErrno(e)
		}

		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, nil
		}
		if e != 0 && e != unix.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}

// BlockingPollUntilStopped polls for events on fd or until a stop is signalled
// on the event fd efd. Returns true if stopped, i.e., efd has event POLLIN.
func BlockingPollUntilStopped(efd int, fd int, events int16) (bool, unix.Errno) {
	pevents := [...]PollEvent{
		{
			FD:     int32(efd),
			Events: unix.POLLIN,
		},
		{
			FD:     int32(fd),
			Events: events,
		},
	}
	_, errno := BlockingPoll(&pevents[0], len(pevents), nil)
	if errno != 0 {
		return pevents[0].Revents&unix.POLLIN != 0, errno
	}

	if pevents[1].Revents&unix.POLLHUP != 0 || pevents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}

	return pevents[0].Revents&unix.POLLIN != 0, errno
}
