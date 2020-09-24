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

// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

// Package fdchannel implements passing file descriptors between processes over
// Unix domain sockets.
package fdchannel

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/gohacks"
)

// int32 is the real type of a file descriptor.
const sizeofInt32 = int(unsafe.Sizeof(int32(0)))

// NewConnectedSockets returns a pair of file descriptors, owned by the caller,
// representing connected sockets that may be passed to separate calls to
// NewEndpoint to create connected Endpoints.
func NewConnectedSockets() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
}

// Endpoint sends file descriptors to, and receives them from, another
// connected Endpoint.
//
// Endpoint is not copyable or movable by value.
type Endpoint struct {
	// +checkatomic
	sockfd int32
	msghdr unix.Msghdr
	cmsg   *unix.Cmsghdr // followed by sizeofInt32 bytes of data
}

// Init must be called on zero-value Endpoints before first use. sockfd must be
// a blocking AF_UNIX SOCK_SEQPACKET socket.
func (ep *Endpoint) Init(sockfd int) {
	// "Datagram sockets in various domains (e.g., the UNIX and Internet
	// domains) permit zero-length datagrams." - recv(2). Experimentally,
	// sendmsg+recvmsg for a zero-length datagram is slightly faster than
	// sendmsg+recvmsg for a single byte over a stream socket.
	cmsgSlice := make([]byte, unix.CmsgSpace(sizeofInt32))
	cmsgSliceHdr := (*gohacks.SliceHeader)(unsafe.Pointer(&cmsgSlice))
	atomic.StoreInt32(&ep.sockfd, int32(sockfd))
	ep.msghdr.Control = (*byte)(cmsgSliceHdr.Data)
	ep.cmsg = (*unix.Cmsghdr)(cmsgSliceHdr.Data)
	// ep.msghdr.Controllen and ep.cmsg.* are mutated by recvmsg(2), so they're
	// set before calling sendmsg/recvmsg.
}

// NewEndpoint is a convenience function that returns an initialized Endpoint
// allocated on the heap.
func NewEndpoint(sockfd int) *Endpoint {
	ep := &Endpoint{}
	ep.Init(sockfd)
	return ep
}

// Destroy releases resources owned by ep. No other Endpoint methods may be
// called after Destroy.
func (ep *Endpoint) Destroy() {
	if sockfd := atomic.SwapInt32(&ep.sockfd, -1); sockfd >= 0 {
		unix.Close(int(sockfd))
	}
}

// Shutdown causes concurrent and future calls to ep.SendFD(), ep.RecvFD(), and
// ep.RecvFDNonblock(), as well as the same calls in the connected Endpoint, to
// unblock and return errors. It does not wait for concurrent calls to return.
//
// Shutdown is the only Endpoint method that may be called concurrently with
// other methods.
func (ep *Endpoint) Shutdown() {
	unix.Shutdown(int(atomic.LoadInt32(&ep.sockfd)), unix.SHUT_RDWR)
}

// SendFD sends the open file description represented by the given file
// descriptor to the connected Endpoint.
func (ep *Endpoint) SendFD(fd int) error {
	cmsgLen := unix.CmsgLen(sizeofInt32)
	ep.cmsg.Level = unix.SOL_SOCKET
	ep.cmsg.Type = unix.SCM_RIGHTS
	ep.cmsg.SetLen(cmsgLen)
	*ep.cmsgData() = int32(fd)
	ep.msghdr.SetControllen(cmsgLen)
	_, _, e := unix.Syscall(unix.SYS_SENDMSG, uintptr(atomic.LoadInt32(&ep.sockfd)), uintptr(unsafe.Pointer(&ep.msghdr)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// RecvFD receives an open file description from the connected Endpoint and
// returns a file descriptor representing it, owned by the caller.
func (ep *Endpoint) RecvFD() (int, error) {
	return ep.recvFD(false)
}

// RecvFDNonblock receives an open file description from the connected Endpoint
// and returns a file descriptor representing it, owned by the caller. If there
// are no pending receivable open file descriptions, RecvFDNonblock returns
// (<unspecified>, EAGAIN or EWOULDBLOCK).
func (ep *Endpoint) RecvFDNonblock() (int, error) {
	return ep.recvFD(true)
}

func (ep *Endpoint) recvFD(nonblock bool) (int, error) {
	cmsgLen := unix.CmsgLen(sizeofInt32)
	ep.msghdr.SetControllen(cmsgLen)
	var e unix.Errno
	if nonblock {
		_, _, e = unix.RawSyscall(unix.SYS_RECVMSG, uintptr(atomic.LoadInt32(&ep.sockfd)), uintptr(unsafe.Pointer(&ep.msghdr)), unix.MSG_TRUNC|unix.MSG_DONTWAIT)
	} else {
		_, _, e = unix.Syscall(unix.SYS_RECVMSG, uintptr(atomic.LoadInt32(&ep.sockfd)), uintptr(unsafe.Pointer(&ep.msghdr)), unix.MSG_TRUNC)
	}
	if e != 0 {
		return -1, e
	}
	if int(ep.msghdr.Controllen) != cmsgLen {
		return -1, fmt.Errorf("received control message has incorrect length: got %d, wanted %d", ep.msghdr.Controllen, cmsgLen)
	}
	if ep.cmsg.Level != unix.SOL_SOCKET || ep.cmsg.Type != unix.SCM_RIGHTS {
		return -1, fmt.Errorf("received control message has incorrect (level, type): got (%v, %v), wanted (%v, %v)", ep.cmsg.Level, ep.cmsg.Type, unix.SOL_SOCKET, unix.SCM_RIGHTS)
	}
	return int(*ep.cmsgData()), nil
}

func (ep *Endpoint) cmsgData() *int32 {
	// unix.CmsgLen(0) == unix.cmsgAlignOf(unix.SizeofCmsghdr)
	return (*int32)(unsafe.Pointer(uintptr(unsafe.Pointer(ep.cmsg)) + uintptr(unix.CmsgLen(0))))
}
