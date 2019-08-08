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

// Package socket provides the interfaces that need to be provided by socket
// implementations and providers, as well as per family demultiplexing of socket
// creation.
package socket

import (
	"fmt"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// ControlMessages represents the union of unix control messages and tcpip
// control messages.
type ControlMessages struct {
	Unix transport.ControlMessages
	IP   tcpip.ControlMessages
}

// Socket is the interface containing socket syscalls used by the syscall layer
// to redirect them to the appropriate implementation.
type Socket interface {
	fs.FileOperations

	// Connect implements the connect(2) linux syscall.
	Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error

	// Accept implements the accept4(2) linux syscall.
	// Returns fd, real peer address length and error. Real peer address
	// length is only set if len(peer) > 0.
	Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error)

	// Bind implements the bind(2) linux syscall.
	Bind(t *kernel.Task, sockaddr []byte) *syserr.Error

	// Listen implements the listen(2) linux syscall.
	Listen(t *kernel.Task, backlog int) *syserr.Error

	// Shutdown implements the shutdown(2) linux syscall.
	Shutdown(t *kernel.Task, how int) *syserr.Error

	// GetSockOpt implements the getsockopt(2) linux syscall.
	GetSockOpt(t *kernel.Task, level int, name int, outPtr usermem.Addr, outLen int) (interface{}, *syserr.Error)

	// SetSockOpt implements the setsockopt(2) linux syscall.
	SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error

	// GetSockName implements the getsockname(2) linux syscall.
	//
	// addrLen is the address length to be returned to the application, not
	// necessarily the actual length of the address.
	GetSockName(t *kernel.Task) (addr linux.SockAddr, addrLen uint32, err *syserr.Error)

	// GetPeerName implements the getpeername(2) linux syscall.
	//
	// addrLen is the address length to be returned to the application, not
	// necessarily the actual length of the address.
	GetPeerName(t *kernel.Task) (addr linux.SockAddr, addrLen uint32, err *syserr.Error)

	// RecvMsg implements the recvmsg(2) linux syscall.
	//
	// senderAddrLen is the address length to be returned to the application,
	// not necessarily the actual length of the address.
	//
	// flags control how RecvMsg should be completed. msgFlags indicate how
	// the RecvMsg call was completed. Note that control message truncation
	// may still be required even if the MSG_CTRUNC bit is not set in
	// msgFlags. In that case, the caller should set MSG_CTRUNC appropriately.
	//
	// If err != nil, the recv was not successful.
	RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, msgFlags int, senderAddr linux.SockAddr, senderAddrLen uint32, controlMessages ControlMessages, err *syserr.Error)

	// SendMsg implements the sendmsg(2) linux syscall. SendMsg does not take
	// ownership of the ControlMessage on error.
	//
	// If n > 0, err will either be nil or an error from t.Block.
	SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages ControlMessages) (n int, err *syserr.Error)

	// SetRecvTimeout sets the timeout (in ns) for recv operations. Zero means
	// no timeout, and negative means DONTWAIT.
	SetRecvTimeout(nanoseconds int64)

	// RecvTimeout gets the current timeout (in ns) for recv operations. Zero
	// means no timeout, and negative means DONTWAIT.
	RecvTimeout() int64

	// SetSendTimeout sets the timeout (in ns) for send operations. Zero means
	// no timeout, and negative means DONTWAIT.
	SetSendTimeout(nanoseconds int64)

	// SendTimeout gets the current timeout (in ns) for send operations. Zero
	// means no timeout, and negative means DONTWAIT.
	SendTimeout() int64

	// State returns the current state of the socket, as represented by Linux in
	// procfs. The returned state value is protocol-specific.
	State() uint32

	// Type returns the family, socket type and protocol of the socket.
	Type() (family int, skType linux.SockType, protocol int)
}

// Provider is the interface implemented by providers of sockets for specific
// address families (e.g., AF_INET).
type Provider interface {
	// Socket creates a new socket.
	//
	// If a nil Socket _and_ a nil error is returned, it means that the
	// protocol is not supported. A non-nil error should only be returned
	// if the protocol is supported, but an error occurs during creation.
	Socket(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *syserr.Error)

	// Pair creates a pair of connected sockets.
	//
	// See Socket for error information.
	Pair(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error)
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
func New(t *kernel.Task, family int, stype linux.SockType, protocol int) (*fs.File, *syserr.Error) {
	for _, p := range families[family] {
		s, err := p.Socket(t, stype, protocol)
		if err != nil {
			return nil, err
		}
		if s != nil {
			t.Kernel().RecordSocket(s)
			return s, nil
		}
	}

	return nil, syserr.ErrAddressFamilyNotSupported
}

// Pair creates a new connected socket pair with the given family, type and
// protocol.
func Pair(t *kernel.Task, family int, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	providers, ok := families[family]
	if !ok {
		return nil, nil, syserr.ErrAddressFamilyNotSupported
	}

	for _, p := range providers {
		s1, s2, err := p.Pair(t, stype, protocol)
		if err != nil {
			return nil, nil, err
		}
		if s1 != nil && s2 != nil {
			k := t.Kernel()
			k.RecordSocket(s1)
			k.RecordSocket(s2)
			return s1, s2, nil
		}
	}

	return nil, nil, syserr.ErrSocketNotSupported
}

// NewDirent returns a sockfs fs.Dirent that resides on device d.
func NewDirent(ctx context.Context, d *device.Device) *fs.Dirent {
	ino := d.NextIno()
	iops := &fsutil.SimpleFileInode{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.FileOwnerFromContext(ctx), fs.FilePermissions{
			User: fs.PermMask{Read: true, Write: true},
		}, linux.SOCKFS_MAGIC),
	}
	inode := fs.NewInode(ctx, iops, fs.NewPseudoMountSource(ctx), fs.StableAttr{
		Type:      fs.Socket,
		DeviceID:  d.DeviceID(),
		InodeID:   ino,
		BlockSize: usermem.PageSize,
	})

	// Dirent name matches net/socket.c:sockfs_dname.
	return fs.NewDirent(ctx, inode, fmt.Sprintf("socket:[%d]", ino))
}

// SendReceiveTimeout stores timeouts for send and receive calls.
//
// It is meant to be embedded into Socket implementations to help satisfy the
// interface.
//
// Care must be taken when copying SendReceiveTimeout as it contains atomic
// variables.
//
// +stateify savable
type SendReceiveTimeout struct {
	// send is length of the send timeout in nanoseconds.
	//
	// send must be accessed atomically.
	send int64

	// recv is length of the receive timeout in nanoseconds.
	//
	// recv must be accessed atomically.
	recv int64
}

// SetRecvTimeout implements Socket.SetRecvTimeout.
func (to *SendReceiveTimeout) SetRecvTimeout(nanoseconds int64) {
	atomic.StoreInt64(&to.recv, nanoseconds)
}

// RecvTimeout implements Socket.RecvTimeout.
func (to *SendReceiveTimeout) RecvTimeout() int64 {
	return atomic.LoadInt64(&to.recv)
}

// SetSendTimeout implements Socket.SetSendTimeout.
func (to *SendReceiveTimeout) SetSendTimeout(nanoseconds int64) {
	atomic.StoreInt64(&to.send, nanoseconds)
}

// SendTimeout implements Socket.SendTimeout.
func (to *SendReceiveTimeout) SendTimeout() int64 {
	return atomic.LoadInt64(&to.send)
}

// GetSockOptEmitUnimplementedEvent emits unimplemented event if name is valid.
// It contains names that are valid for GetSockOpt when level is SOL_SOCKET.
func GetSockOptEmitUnimplementedEvent(t *kernel.Task, name int) {
	switch name {
	case linux.SO_ACCEPTCONN,
		linux.SO_BPF_EXTENSIONS,
		linux.SO_COOKIE,
		linux.SO_DOMAIN,
		linux.SO_ERROR,
		linux.SO_GET_FILTER,
		linux.SO_INCOMING_NAPI_ID,
		linux.SO_MEMINFO,
		linux.SO_PEERCRED,
		linux.SO_PEERGROUPS,
		linux.SO_PEERNAME,
		linux.SO_PEERSEC,
		linux.SO_PROTOCOL,
		linux.SO_SNDLOWAT,
		linux.SO_TYPE:

		t.Kernel().EmitUnimplementedEvent(t)

	default:
		emitUnimplementedEvent(t, name)
	}
}

// SetSockOptEmitUnimplementedEvent emits unimplemented event if name is valid.
// It contains names that are valid for SetSockOpt when level is SOL_SOCKET.
func SetSockOptEmitUnimplementedEvent(t *kernel.Task, name int) {
	switch name {
	case linux.SO_ATTACH_BPF,
		linux.SO_ATTACH_FILTER,
		linux.SO_ATTACH_REUSEPORT_CBPF,
		linux.SO_ATTACH_REUSEPORT_EBPF,
		linux.SO_CNX_ADVICE,
		linux.SO_DETACH_FILTER,
		linux.SO_RCVBUFFORCE,
		linux.SO_SNDBUFFORCE:

		t.Kernel().EmitUnimplementedEvent(t)

	default:
		emitUnimplementedEvent(t, name)
	}
}

// emitUnimplementedEvent emits unimplemented event if name is valid. It
// contains names that are common between Get and SetSocketOpt when level is
// SOL_SOCKET.
func emitUnimplementedEvent(t *kernel.Task, name int) {
	switch name {
	case linux.SO_BINDTODEVICE,
		linux.SO_BROADCAST,
		linux.SO_BSDCOMPAT,
		linux.SO_BUSY_POLL,
		linux.SO_DEBUG,
		linux.SO_DONTROUTE,
		linux.SO_INCOMING_CPU,
		linux.SO_KEEPALIVE,
		linux.SO_LINGER,
		linux.SO_LOCK_FILTER,
		linux.SO_MARK,
		linux.SO_MAX_PACING_RATE,
		linux.SO_NOFCS,
		linux.SO_NO_CHECK,
		linux.SO_OOBINLINE,
		linux.SO_PASSCRED,
		linux.SO_PASSSEC,
		linux.SO_PEEK_OFF,
		linux.SO_PRIORITY,
		linux.SO_RCVBUF,
		linux.SO_RCVLOWAT,
		linux.SO_RCVTIMEO,
		linux.SO_REUSEADDR,
		linux.SO_REUSEPORT,
		linux.SO_RXQ_OVFL,
		linux.SO_SELECT_ERR_QUEUE,
		linux.SO_SNDBUF,
		linux.SO_SNDTIMEO,
		linux.SO_TIMESTAMP,
		linux.SO_TIMESTAMPING,
		linux.SO_TIMESTAMPNS,
		linux.SO_TXTIME,
		linux.SO_WIFI_STATUS,
		linux.SO_ZEROCOPY:

		t.Kernel().EmitUnimplementedEvent(t)
	}
}

// UnmarshalSockAddr unmarshals memory representing a struct sockaddr to one of
// the ABI socket address types.
//
// Precondition: data must be long enough to represent a socket address of the
// given family.
func UnmarshalSockAddr(family int, data []byte) linux.SockAddr {
	switch family {
	case syscall.AF_INET:
		var addr linux.SockAddrInet
		binary.Unmarshal(data[:syscall.SizeofSockaddrInet4], usermem.ByteOrder, &addr)
		return &addr
	case syscall.AF_INET6:
		var addr linux.SockAddrInet6
		binary.Unmarshal(data[:syscall.SizeofSockaddrInet6], usermem.ByteOrder, &addr)
		return &addr
	case syscall.AF_UNIX:
		var addr linux.SockAddrUnix
		binary.Unmarshal(data[:syscall.SizeofSockaddrUnix], usermem.ByteOrder, &addr)
		return &addr
	case syscall.AF_NETLINK:
		var addr linux.SockAddrNetlink
		binary.Unmarshal(data[:syscall.SizeofSockaddrNetlink], usermem.ByteOrder, &addr)
		return &addr
	default:
		panic(fmt.Sprintf("Unsupported socket family %v", family))
	}
}
