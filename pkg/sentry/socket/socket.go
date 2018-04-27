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

// Package socket provides the interfaces that need to be provided by socket
// implementations and providers, as well as per family demultiplexing of socket
// creation.
package socket

import (
	"fmt"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
)

// Socket is the interface containing socket syscalls used by the syscall layer
// to redirect them to the appropriate implementation.
type Socket interface {
	fs.FileOperations

	// Connect implements the connect(2) linux syscall.
	Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error

	// Accept implements the accept4(2) linux syscall.
	// Returns fd, real peer address length and error. Real peer address
	// length is only set if len(peer) > 0.
	Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (kdefs.FD, interface{}, uint32, *syserr.Error)

	// Bind implements the bind(2) linux syscall.
	Bind(t *kernel.Task, sockaddr []byte) *syserr.Error

	// Listen implements the listen(2) linux syscall.
	Listen(t *kernel.Task, backlog int) *syserr.Error

	// Shutdown implements the shutdown(2) linux syscall.
	Shutdown(t *kernel.Task, how int) *syserr.Error

	// GetSockOpt implements the getsockopt(2) linux syscall.
	GetSockOpt(t *kernel.Task, level int, name int, outLen int) (interface{}, *syserr.Error)

	// SetSockOpt implements the setsockopt(2) linux syscall.
	SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error

	// GetSockName implements the getsockname(2) linux syscall.
	//
	// addrLen is the address length to be returned to the application, not
	// necessarily the actual length of the address.
	GetSockName(t *kernel.Task) (addr interface{}, addrLen uint32, err *syserr.Error)

	// GetPeerName implements the getpeername(2) linux syscall.
	//
	// addrLen is the address length to be returned to the application, not
	// necessarily the actual length of the address.
	GetPeerName(t *kernel.Task) (addr interface{}, addrLen uint32, err *syserr.Error)

	// RecvMsg implements the recvmsg(2) linux syscall.
	//
	// senderAddrLen is the address length to be returned to the application,
	// not necessarily the actual length of the address.
	RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, senderAddr interface{}, senderAddrLen uint32, controlMessages unix.ControlMessages, err *syserr.Error)

	// SendMsg implements the sendmsg(2) linux syscall. SendMsg does not take
	// ownership of the ControlMessage on error.
	SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, controlMessages unix.ControlMessages) (n int, err *syserr.Error)

	// SetRecvTimeout sets the timeout (in ns) for recv operations. Zero means
	// no timeout.
	SetRecvTimeout(nanoseconds int64)

	// RecvTimeout gets the current timeout (in ns) for recv operations. Zero
	// means no timeout.
	RecvTimeout() int64
}

// Provider is the interface implemented by providers of sockets for specific
// address families (e.g., AF_INET).
type Provider interface {
	// Socket creates a new socket.
	//
	// If a nil Socket _and_ a nil error is returned, it means that the
	// protocol is not supported. A non-nil error should only be returned
	// if the protocol is supported, but an error occurs during creation.
	Socket(t *kernel.Task, stype unix.SockType, protocol int) (*fs.File, *syserr.Error)

	// Pair creates a pair of connected sockets.
	//
	// See Socket for error information.
	Pair(t *kernel.Task, stype unix.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error)
}

// families holds a map of all known address families and their providers.
var families = make(map[int][]Provider)

// RegisterProvider registers the provider of a given address family so that
// sockets of that type can be created via socket() and/or socketpair()
// syscalls.
func RegisterProvider(family int, provider Provider) {
	families[family] = append(families[family], provider)
}

// New creates a new socket with the given family, type and protocol.
func New(t *kernel.Task, family int, stype unix.SockType, protocol int) (*fs.File, *syserr.Error) {
	for _, p := range families[family] {
		s, err := p.Socket(t, stype, protocol)
		if err != nil {
			return nil, err
		}
		if s != nil {
			return s, nil
		}
	}

	return nil, syserr.ErrAddressFamilyNotSupported
}

// Pair creates a new connected socket pair with the given family, type and
// protocol.
func Pair(t *kernel.Task, family int, stype unix.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	providers, ok := families[family]
	if !ok {
		return nil, nil, syserr.ErrAddressFamilyNotSupported
	}

	for _, p := range providers {
		s, t, err := p.Pair(t, stype, protocol)
		if err != nil {
			return nil, nil, err
		}
		if s != nil && t != nil {
			return s, t, nil
		}
	}

	return nil, nil, syserr.ErrSocketNotSupported
}

// NewDirent returns a sockfs fs.Dirent that resides on device d.
func NewDirent(ctx context.Context, d *device.Device) *fs.Dirent {
	ino := d.NextIno()
	// There is no real filesystem backing this pipe, so we pass in a nil
	// Filesystem.
	inode := fs.NewInode(fsutil.NewSimpleInodeOperations(fsutil.InodeSimpleAttributes{
		FSType: linux.SOCKFS_MAGIC,
		UAttr: fs.WithCurrentTime(ctx, fs.UnstableAttr{
			Owner: fs.FileOwnerFromContext(ctx),
			Perms: fs.FilePermissions{
				User: fs.PermMask{Read: true, Write: true},
			},
			Links: 1,
		}),
	}), fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{}), fs.StableAttr{
		Type:      fs.Socket,
		DeviceID:  d.DeviceID(),
		InodeID:   ino,
		BlockSize: usermem.PageSize,
	})

	// Dirent name matches net/socket.c:sockfs_dname.
	return fs.NewDirent(inode, fmt.Sprintf("socket:[%d]", ino))
}

// ReceiveTimeout stores a timeout for receive calls.
//
// It is meant to be embedded into Socket implementations to help satisfy the
// interface.
//
// Care must be taken when copying ReceiveTimeout as it contains atomic
// variables.
type ReceiveTimeout struct {
	// ns is length of the timeout in nanoseconds.
	//
	// ns must be accessed atomically.
	ns int64
}

// SetRecvTimeout implements Socket.SetRecvTimeout.
func (rt *ReceiveTimeout) SetRecvTimeout(nanoseconds int64) {
	atomic.StoreInt64(&rt.ns, nanoseconds)
}

// RecvTimeout implements Socket.RecvTimeout.
func (rt *ReceiveTimeout) RecvTimeout() int64 {
	return atomic.LoadInt64(&rt.ns)
}
