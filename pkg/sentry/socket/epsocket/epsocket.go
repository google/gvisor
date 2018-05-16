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

// Package epsocket provides an implementation of the socket.Socket interface
// that is backed by a tcpip.Endpoint.
//
// It does not depend on any particular endpoint implementation, and thus can
// be used to expose certain endpoints to the sentry while leaving others out,
// for example, TCP endpoints and Unix-domain endpoints.
//
// Lock ordering: netstack => mm: ioSequencePayload copies user memory inside
// tcpip.Endpoint.Write(). Netstack is allowed to (and does) hold locks during
// this operation.
package epsocket

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const sizeOfInt32 int = 4

// ntohs converts a 16-bit number from network byte order to host byte order. It
// assumes that the host is little endian.
func ntohs(v uint16) uint16 {
	return v<<8 | v>>8
}

// htons converts a 16-bit number from host byte order to network byte order. It
// assumes that the host is little endian.
func htons(v uint16) uint16 {
	return ntohs(v)
}

// commonEndpoint represents the intersection of a tcpip.Endpoint and a
// unix.Endpoint.
type commonEndpoint interface {
	// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress and
	// unix.Endpoint.GetLocalAddress.
	GetLocalAddress() (tcpip.FullAddress, *tcpip.Error)

	// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress and
	// unix.Endpoint.GetRemoteAddress.
	GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error)

	// Readiness implements tcpip.Endpoint.Readiness and
	// unix.Endpoint.Readiness.
	Readiness(mask waiter.EventMask) waiter.EventMask

	// SetSockOpt implements tcpip.Endpoint.SetSockOpt and
	// unix.Endpoint.SetSockOpt.
	SetSockOpt(interface{}) *tcpip.Error

	// GetSockOpt implements tcpip.Endpoint.GetSockOpt and
	// unix.Endpoint.GetSockOpt.
	GetSockOpt(interface{}) *tcpip.Error
}

// SocketOperations encapsulates all the state needed to represent a network stack
// endpoint in the kernel context.
type SocketOperations struct {
	socket.ReceiveTimeout
	fsutil.PipeSeek      `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoFsync       `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoMMap        `state:"nosave"`
	*waiter.Queue

	family   int
	Endpoint tcpip.Endpoint
	skType   unix.SockType

	// readMu protects access to readView, control, and sender.
	readMu   sync.Mutex `state:"nosave"`
	readView buffer.View
	readCM   tcpip.ControlMessages
	sender   tcpip.FullAddress
}

// New creates a new endpoint socket.
func New(t *kernel.Task, family int, skType unix.SockType, queue *waiter.Queue, endpoint tcpip.Endpoint) *fs.File {
	dirent := socket.NewDirent(t, epsocketDevice)
	defer dirent.DecRef()
	return fs.NewFile(t, dirent, fs.FileFlags{Read: true, Write: true}, &SocketOperations{
		Queue:    queue,
		family:   family,
		Endpoint: endpoint,
		skType:   skType,
	})
}

var sockAddrInetSize = int(binary.Size(linux.SockAddrInet{}))
var sockAddrInet6Size = int(binary.Size(linux.SockAddrInet6{}))

// GetAddress reads an sockaddr struct from the given address and converts it
// to the FullAddress format. It supports AF_UNIX, AF_INET and AF_INET6
// addresses.
func GetAddress(sfamily int, addr []byte) (tcpip.FullAddress, *syserr.Error) {
	// Make sure we have at least 2 bytes for the address family.
	if len(addr) < 2 {
		return tcpip.FullAddress{}, syserr.ErrInvalidArgument
	}

	family := usermem.ByteOrder.Uint16(addr)
	if family != uint16(sfamily) {
		return tcpip.FullAddress{}, syserr.ErrAddressFamilyNotSupported
	}

	// Get the rest of the fields based on the address family.
	switch family {
	case linux.AF_UNIX:
		path := addr[2:]
		// Drop the terminating NUL (if one exists) and everything after it.
		// Skip the first byte, which is NUL for abstract paths.
		if len(path) > 1 {
			if n := bytes.IndexByte(path[1:], 0); n >= 0 {
				path = path[:n+1]
			}
		}
		return tcpip.FullAddress{
			Addr: tcpip.Address(path),
		}, nil

	case linux.AF_INET:
		var a linux.SockAddrInet
		if len(addr) < sockAddrInetSize {
			return tcpip.FullAddress{}, syserr.ErrBadAddress
		}
		binary.Unmarshal(addr[:sockAddrInetSize], usermem.ByteOrder, &a)

		out := tcpip.FullAddress{
			Addr: tcpip.Address(a.Addr[:]),
			Port: ntohs(a.Port),
		}
		if out.Addr == "\x00\x00\x00\x00" {
			out.Addr = ""
		}
		return out, nil

	case linux.AF_INET6:
		var a linux.SockAddrInet6
		if len(addr) < sockAddrInet6Size {
			return tcpip.FullAddress{}, syserr.ErrBadAddress
		}
		binary.Unmarshal(addr[:sockAddrInet6Size], usermem.ByteOrder, &a)

		out := tcpip.FullAddress{
			Addr: tcpip.Address(a.Addr[:]),
			Port: ntohs(a.Port),
		}
		if isLinkLocal(out.Addr) {
			out.NIC = tcpip.NICID(a.Scope_id)
		}
		if out.Addr == tcpip.Address(strings.Repeat("\x00", 16)) {
			out.Addr = ""
		}
		return out, nil

	default:
		return tcpip.FullAddress{}, syserr.ErrAddressFamilyNotSupported
	}
}

func (s *SocketOperations) isPacketBased() bool {
	return s.skType == linux.SOCK_DGRAM || s.skType == linux.SOCK_SEQPACKET || s.skType == linux.SOCK_RDM
}

// fetchReadView updates the readView field of the socket if it's currently
// empty. It assumes that the socket is locked.
func (s *SocketOperations) fetchReadView() *syserr.Error {
	if len(s.readView) > 0 {
		return nil
	}

	s.readView = nil
	s.sender = tcpip.FullAddress{}

	v, cms, err := s.Endpoint.Read(&s.sender)
	if err != nil {
		return syserr.TranslateNetstackError(err)
	}

	s.readView = v
	s.readCM = cms

	return nil
}

// Release implements fs.FileOperations.Release.
func (s *SocketOperations) Release() {
	s.Endpoint.Close()
}

// Read implements fs.FileOperations.Read.
func (s *SocketOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	n, _, _, _, err := s.nonBlockingRead(ctx, dst, false, false, false)
	if err == syserr.ErrWouldBlock {
		return int64(n), syserror.ErrWouldBlock
	}
	if err != nil {
		return 0, err.ToError()
	}
	return int64(n), nil
}

// ioSequencePayload implements tcpip.Payload. It copies user memory bytes on demand
// based on the requested size.
type ioSequencePayload struct {
	ctx context.Context
	src usermem.IOSequence
}

// Get implements tcpip.Payload.
func (i *ioSequencePayload) Get(size int) ([]byte, *tcpip.Error) {
	if size > i.Size() {
		size = i.Size()
	}
	v := buffer.NewView(size)
	if _, err := i.src.CopyIn(i.ctx, v); err != nil {
		return nil, tcpip.ErrBadAddress
	}
	return v, nil
}

// Size implements tcpip.Payload.
func (i *ioSequencePayload) Size() int {
	return int(i.src.NumBytes())
}

// Write implements fs.FileOperations.Write.
func (s *SocketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	f := &ioSequencePayload{ctx: ctx, src: src}
	n, err := s.Endpoint.Write(f, tcpip.WriteOptions{})
	if err == tcpip.ErrWouldBlock {
		return int64(n), syserror.ErrWouldBlock
	}
	return int64(n), syserr.TranslateNetstackError(err).ToError()
}

// Readiness returns a mask of ready events for socket s.
func (s *SocketOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	r := s.Endpoint.Readiness(mask)

	// Check our cached value iff the caller asked for readability and the
	// endpoint itself is currently not readable.
	if (mask & ^r & waiter.EventIn) != 0 {
		s.readMu.Lock()
		if len(s.readView) > 0 {
			r |= waiter.EventIn
		}
		s.readMu.Unlock()
	}

	return r
}

// Connect implements the linux syscall connect(2) for sockets backed by
// tpcip.Endpoint.
func (s *SocketOperations) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	addr, err := GetAddress(s.family, sockaddr)
	if err != nil {
		return err
	}

	// Always return right away in the non-blocking case.
	if !blocking {
		return syserr.TranslateNetstackError(s.Endpoint.Connect(addr))
	}

	// Register for notification when the endpoint becomes writable, then
	// initiate the connection.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	if err := s.Endpoint.Connect(addr); err != tcpip.ErrConnectStarted && err != tcpip.ErrAlreadyConnecting {
		return syserr.TranslateNetstackError(err)
	}

	// It's pending, so we have to wait for a notification, and fetch the
	// result once the wait completes.
	if err := t.Block(ch); err != nil {
		return syserr.FromError(err)
	}

	// Call Connect() again after blocking to find connect's result.
	return syserr.TranslateNetstackError(s.Endpoint.Connect(addr))
}

// Bind implements the linux syscall bind(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	addr, err := GetAddress(s.family, sockaddr)
	if err != nil {
		return err
	}

	// Issue the bind request to the endpoint.
	return syserr.TranslateNetstackError(s.Endpoint.Bind(addr, nil))
}

// Listen implements the linux syscall listen(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return syserr.TranslateNetstackError(s.Endpoint.Listen(backlog))
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *SocketOperations) blockingAccept(t *kernel.Task) (tcpip.Endpoint, *waiter.Queue, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	// Try to accept the connection again; if it fails, then wait until we
	// get a notification.
	for {
		if ep, wq, err := s.Endpoint.Accept(); err != tcpip.ErrWouldBlock {
			return ep, wq, syserr.TranslateNetstackError(err)
		}

		if err := t.Block(ch); err != nil {
			return nil, nil, syserr.FromError(err)
		}
	}
}

// Accept implements the linux syscall accept(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (kdefs.FD, interface{}, uint32, *syserr.Error) {
	// Issue the accept request to get the new endpoint.
	ep, wq, err := s.Endpoint.Accept()
	if err != nil {
		if err != tcpip.ErrWouldBlock || !blocking {
			return 0, nil, 0, syserr.TranslateNetstackError(err)
		}

		var err *syserr.Error
		ep, wq, err = s.blockingAccept(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns := New(t, s.family, s.skType, wq, ep)
	defer ns.DecRef()

	if flags&linux.SOCK_NONBLOCK != 0 {
		flags := ns.Flags()
		flags.NonBlocking = true
		ns.SetFlags(flags.Settable())
	}

	var addr interface{}
	var addrLen uint32
	if peerRequested {
		// Get address of the peer and write it to peer slice.
		var err *syserr.Error
		addr, addrLen, err = ns.FileOperations.(*SocketOperations).GetPeerName(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	fdFlags := kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	}
	fd, e := t.FDMap().NewFDFrom(0, ns, fdFlags, t.ThreadGroup().Limits())

	return fd, addr, addrLen, syserr.FromError(e)
}

// ConvertShutdown converts Linux shutdown flags into tcpip shutdown flags.
func ConvertShutdown(how int) (tcpip.ShutdownFlags, *syserr.Error) {
	var f tcpip.ShutdownFlags
	switch how {
	case linux.SHUT_RD:
		f = tcpip.ShutdownRead
	case linux.SHUT_WR:
		f = tcpip.ShutdownWrite
	case linux.SHUT_RDWR:
		f = tcpip.ShutdownRead | tcpip.ShutdownWrite
	default:
		return 0, syserr.ErrInvalidArgument
	}
	return f, nil
}

// Shutdown implements the linux syscall shutdown(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	f, err := ConvertShutdown(how)
	if err != nil {
		return err
	}

	// Issue shutdown request.
	return syserr.TranslateNetstackError(s.Endpoint.Shutdown(f))
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) GetSockOpt(t *kernel.Task, level, name, outLen int) (interface{}, *syserr.Error) {
	return GetSockOpt(t, s, s.Endpoint, s.family, s.skType, level, name, outLen)
}

// GetSockOpt can be used to implement the linux syscall getsockopt(2) for
// sockets backed by a commonEndpoint.
func GetSockOpt(t *kernel.Task, s socket.Socket, ep commonEndpoint, family int, skType unix.SockType, level, name, outLen int) (interface{}, *syserr.Error) {
	switch level {
	case syscall.SOL_SOCKET:
		switch name {
		case linux.SO_TYPE:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}
			return int32(skType), nil

		case linux.SO_ERROR:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			// Get the last error and convert it.
			err := ep.GetSockOpt(tcpip.ErrorOption{})
			if err == nil {
				return int32(0), nil
			}
			return int32(syserr.ToLinux(syserr.TranslateNetstackError(err)).Number()), nil

		case linux.SO_PEERCRED:
			if family != linux.AF_UNIX || outLen < syscall.SizeofUcred {
				return nil, syserr.ErrInvalidArgument
			}

			tcred := t.Credentials()
			return syscall.Ucred{
				Pid: int32(t.ThreadGroup().ID()),
				Uid: uint32(tcred.EffectiveKUID.In(tcred.UserNamespace).OrOverflow()),
				Gid: uint32(tcred.EffectiveKGID.In(tcred.UserNamespace).OrOverflow()),
			}, nil

		case linux.SO_PASSCRED:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var v tcpip.PasscredOption
			if err := ep.GetSockOpt(&v); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			return int32(v), nil

		case linux.SO_SNDBUF:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var size tcpip.SendBufferSizeOption
			if err := ep.GetSockOpt(&size); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			if size > math.MaxInt32 {
				size = math.MaxInt32
			}

			return int32(size), nil

		case linux.SO_RCVBUF:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var size tcpip.ReceiveBufferSizeOption
			if err := ep.GetSockOpt(&size); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			if size > math.MaxInt32 {
				size = math.MaxInt32
			}

			return int32(size), nil

		case linux.SO_REUSEADDR:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var v tcpip.ReuseAddressOption
			if err := ep.GetSockOpt(&v); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			return int32(v), nil

		case linux.SO_KEEPALIVE:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}
			return int32(0), nil

		case linux.SO_LINGER:
			if outLen < syscall.SizeofLinger {
				return nil, syserr.ErrInvalidArgument
			}
			return syscall.Linger{}, nil

		case linux.SO_RCVTIMEO:
			if outLen < linux.SizeOfTimeval {
				return nil, syserr.ErrInvalidArgument
			}

			return linux.NsecToTimeval(s.RecvTimeout()), nil

		case linux.SO_TIMESTAMP:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var v tcpip.TimestampOption
			if err := ep.GetSockOpt(&v); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			return int32(v), nil
		}

	case syscall.SOL_TCP:
		switch name {
		case syscall.TCP_NODELAY:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var v tcpip.NoDelayOption
			if err := ep.GetSockOpt(&v); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			return int32(v), nil

		case syscall.TCP_INFO:
			var v tcpip.TCPInfoOption
			if err := ep.GetSockOpt(&v); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			// TODO: Translate fields once they are added to
			// tcpip.TCPInfoOption.
			info := linux.TCPInfo{}

			// Linux truncates the output binary to outLen.
			ib := binary.Marshal(nil, usermem.ByteOrder, &info)
			if len(ib) > outLen {
				ib = ib[:outLen]
			}

			return ib, nil
		}

	case syscall.SOL_IPV6:
		switch name {
		case syscall.IPV6_V6ONLY:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}

			var v tcpip.V6OnlyOption
			if err := ep.GetSockOpt(&v); err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}

			return int32(v), nil
		}
	}

	return nil, syserr.ErrProtocolNotAvailable
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	return SetSockOpt(t, s, s.Endpoint, level, name, optVal)
}

// SetSockOpt can be used to implement the linux syscall setsockopt(2) for
// sockets backed by a commonEndpoint.
func SetSockOpt(t *kernel.Task, s socket.Socket, ep commonEndpoint, level int, name int, optVal []byte) *syserr.Error {
	switch level {
	case syscall.SOL_SOCKET:
		switch name {
		case linux.SO_SNDBUF:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.SendBufferSizeOption(v)))

		case linux.SO_RCVBUF:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(v)))

		case linux.SO_REUSEADDR:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.ReuseAddressOption(v)))

		case linux.SO_PASSCRED:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.PasscredOption(v)))

		case linux.SO_RCVTIMEO:
			if len(optVal) < linux.SizeOfTimeval {
				return syserr.ErrInvalidArgument
			}

			var v linux.Timeval
			binary.Unmarshal(optVal[:linux.SizeOfTimeval], usermem.ByteOrder, &v)
			s.SetRecvTimeout(v.ToNsecCapped())
			return nil

		case linux.SO_TIMESTAMP:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.TimestampOption(v)))
		}

	case syscall.SOL_TCP:
		switch name {
		case syscall.TCP_NODELAY:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.NoDelayOption(v)))
		}
	case syscall.SOL_IPV6:
		switch name {
		case syscall.IPV6_V6ONLY:
			if len(optVal) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}

			v := usermem.ByteOrder.Uint32(optVal)
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.V6OnlyOption(v)))
		}
	}

	// FIXME: Disallow IP-level multicast group options by
	// default. These will need to be supported by appropriately plumbing
	// the level through to the network stack (if at all). However, we
	// still allow setting TTL, and multicast-enable/disable type options.
	if level == 0 {
		const (
			_IP_ADD_MEMBERSHIP = 35
			_MCAST_JOIN_GROUP  = 42
		)
		if name == _IP_ADD_MEMBERSHIP || name == _MCAST_JOIN_GROUP {
			return syserr.ErrInvalidArgument
		}
	}

	// Default to the old behavior; hand off to network stack.
	return syserr.TranslateNetstackError(ep.SetSockOpt(struct{}{}))
}

// isLinkLocal determines if the given IPv6 address is link-local. This is the
// case when it has the fe80::/10 prefix. This check is used to determine when
// the NICID is relevant for a given IPv6 address.
func isLinkLocal(addr tcpip.Address) bool {
	return len(addr) >= 2 && addr[0] == 0xfe && addr[1]&0xc0 == 0x80
}

// ConvertAddress converts the given address to a native format.
func ConvertAddress(family int, addr tcpip.FullAddress) (interface{}, uint32) {
	switch family {
	case linux.AF_UNIX:
		var out linux.SockAddrUnix
		out.Family = linux.AF_UNIX
		for i := 0; i < len([]byte(addr.Addr)); i++ {
			out.Path[i] = int8(addr.Addr[i])
		}
		// Linux just returns the header for empty addresses.
		if len(addr.Addr) == 0 {
			return out, 2
		}
		// Linux returns the used length of the address struct (including the
		// null terminator) for filesystem paths. The Family field is 2 bytes.
		// It is sometimes allowed to exclude the null terminator if the
		// address length is the max. Abstract paths always return the full
		// length.
		if out.Path[0] == 0 || len([]byte(addr.Addr)) == len(out.Path) {
			return out, uint32(binary.Size(out))
		}
		return out, uint32(3 + len(addr.Addr))
	case linux.AF_INET:
		var out linux.SockAddrInet
		copy(out.Addr[:], addr.Addr)
		out.Family = linux.AF_INET
		out.Port = htons(addr.Port)
		return out, uint32(binary.Size(out))
	case linux.AF_INET6:
		var out linux.SockAddrInet6
		if len(addr.Addr) == 4 {
			// Copy address is v4-mapped format.
			copy(out.Addr[12:], addr.Addr)
			out.Addr[10] = 0xff
			out.Addr[11] = 0xff
		} else {
			copy(out.Addr[:], addr.Addr)
		}
		out.Family = linux.AF_INET6
		out.Port = htons(addr.Port)
		if isLinkLocal(addr.Addr) {
			out.Scope_id = uint32(addr.NIC)
		}
		return out, uint32(binary.Size(out))
	default:
		return nil, 0
	}
}

// GetSockName implements the linux syscall getsockname(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) GetSockName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr, err := s.Endpoint.GetLocalAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := ConvertAddress(s.family, addr)
	return a, l, nil
}

// GetPeerName implements the linux syscall getpeername(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) GetPeerName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr, err := s.Endpoint.GetRemoteAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := ConvertAddress(s.family, addr)
	return a, l, nil
}

// coalescingRead is the fast path for non-blocking, non-peek, stream-based
// case. It coalesces as many packets as possible before returning to the
// caller.
func (s *SocketOperations) coalescingRead(ctx context.Context, dst usermem.IOSequence, discard bool) (int, *syserr.Error) {
	var err *syserr.Error
	var copied int

	// Copy as many views as possible into the user-provided buffer.
	for dst.NumBytes() != 0 {
		err = s.fetchReadView()
		if err != nil {
			break
		}

		var n int
		var e error
		if discard {
			n = len(s.readView)
			if int64(n) > dst.NumBytes() {
				n = int(dst.NumBytes())
			}
		} else {
			n, e = dst.CopyOut(ctx, s.readView)
		}
		copied += n
		s.readView.TrimFront(n)
		dst = dst.DropFirst(n)
		if e != nil {
			err = syserr.FromError(e)
			break
		}
	}

	// If we managed to copy something, we must deliver it.
	if copied > 0 {
		return copied, nil
	}

	return 0, err
}

// nonBlockingRead issues a non-blocking read.
//
// TODO: Support timestamps for stream sockets.
func (s *SocketOperations) nonBlockingRead(ctx context.Context, dst usermem.IOSequence, peek, trunc, senderRequested bool) (int, interface{}, uint32, socket.ControlMessages, *syserr.Error) {
	isPacket := s.isPacketBased()

	// Fast path for regular reads from stream (e.g., TCP) endpoints. Note
	// that senderRequested is ignored for stream sockets.
	if !peek && !isPacket {
		// TCP sockets discard the data if MSG_TRUNC is set.
		//
		// This behavior is documented in man 7 tcp:
		// Since version 2.4, Linux supports the use of MSG_TRUNC in the flags
		// argument of recv(2) (and recvmsg(2)). This flag causes the received
		// bytes of data to be discarded, rather than passed back in a
		// caller-supplied  buffer.
		s.readMu.Lock()
		n, err := s.coalescingRead(ctx, dst, trunc)
		s.readMu.Unlock()
		return n, nil, 0, socket.ControlMessages{}, err
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if err := s.fetchReadView(); err != nil {
		return 0, nil, 0, socket.ControlMessages{}, err
	}

	if !isPacket && peek && trunc {
		// MSG_TRUNC with MSG_PEEK on a TCP socket returns the
		// amount that could be read.
		var rql tcpip.ReceiveQueueSizeOption
		if err := s.Endpoint.GetSockOpt(&rql); err != nil {
			return 0, nil, 0, socket.ControlMessages{}, syserr.TranslateNetstackError(err)
		}
		available := len(s.readView) + int(rql)
		bufLen := int(dst.NumBytes())
		if available < bufLen {
			return available, nil, 0, socket.ControlMessages{}, nil
		}
		return bufLen, nil, 0, socket.ControlMessages{}, nil
	}

	n, err := dst.CopyOut(ctx, s.readView)
	var addr interface{}
	var addrLen uint32
	if isPacket && senderRequested {
		addr, addrLen = ConvertAddress(s.family, s.sender)
	}

	if peek {
		if l := len(s.readView); trunc && l > n {
			// isPacket must be true.
			return l, addr, addrLen, socket.ControlMessages{IP: s.readCM}, syserr.FromError(err)
		}

		if isPacket || err != nil {
			return int(n), addr, addrLen, socket.ControlMessages{IP: s.readCM}, syserr.FromError(err)
		}

		// We need to peek beyond the first message.
		dst = dst.DropFirst(n)
		num, err := dst.CopyOutFrom(ctx, safemem.FromVecReaderFunc{func(dsts [][]byte) (int64, error) {
			n, _, err := s.Endpoint.Peek(dsts)
			// TODO: Handle peek timestamp.
			if err != nil {
				return int64(n), syserr.TranslateNetstackError(err).ToError()
			}
			return int64(n), nil
		}})
		n += int(num)
		if err == syserror.ErrWouldBlock && n > 0 {
			// We got some data, so no need to return an error.
			err = nil
		}
		return int(n), nil, 0, socket.ControlMessages{IP: s.readCM}, syserr.FromError(err)
	}

	var msgLen int
	if isPacket {
		msgLen = len(s.readView)
		s.readView = nil
	} else {
		msgLen = int(n)
		s.readView.TrimFront(int(n))
	}

	if trunc {
		return msgLen, addr, addrLen, socket.ControlMessages{IP: s.readCM}, syserr.FromError(err)
	}

	return int(n), addr, addrLen, socket.ControlMessages{IP: s.readCM}, syserr.FromError(err)
}

// RecvMsg implements the linux syscall recvmsg(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, senderAddr interface{}, senderAddrLen uint32, controlMessages socket.ControlMessages, err *syserr.Error) {
	trunc := flags&linux.MSG_TRUNC != 0

	peek := flags&linux.MSG_PEEK != 0
	if senderRequested && !s.isPacketBased() {
		// Stream sockets ignore the sender address.
		senderRequested = false
	}
	n, senderAddr, senderAddrLen, controlMessages, err = s.nonBlockingRead(t, dst, peek, trunc, senderRequested)
	if err != syserr.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return
	}

	// We'll have to block. Register for notifications and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		n, senderAddr, senderAddrLen, controlMessages, err = s.nonBlockingRead(t, dst, peek, trunc, senderRequested)
		if err != syserr.ErrWouldBlock {
			return
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

// SendMsg implements the linux syscall sendmsg(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	// Reject Unix control messages.
	if !controlMessages.Unix.Empty() {
		return 0, syserr.ErrInvalidArgument
	}

	var addr *tcpip.FullAddress
	if len(to) > 0 {
		addrBuf, err := GetAddress(s.family, to)
		if err != nil {
			return 0, err
		}

		addr = &addrBuf
	}

	v := buffer.NewView(int(src.NumBytes()))

	// Copy all the data into the buffer.
	if _, err := src.CopyIn(t, v); err != nil {
		return 0, syserr.FromError(err)
	}

	opts := tcpip.WriteOptions{
		To:          addr,
		More:        flags&linux.MSG_MORE != 0,
		EndOfRecord: flags&linux.MSG_EOR != 0,
	}

	n, err := s.Endpoint.Write(tcpip.SlicePayload(v), opts)
	if err != tcpip.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), syserr.TranslateNetstackError(err)
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	v.TrimFront(int(n))
	total := n
	for {
		n, err = s.Endpoint.Write(tcpip.SlicePayload(v), opts)
		v.TrimFront(int(n))
		total += n
		if err != tcpip.ErrWouldBlock {
			return int(total), syserr.TranslateNetstackError(err)
		}

		if err := t.Block(ch); err != nil {
			return int(total), syserr.FromError(err)
		}
	}
}

// interfaceIoctl implements interface requests.
func (s *SocketOperations) interfaceIoctl(ctx context.Context, io usermem.IO, arg int, ifr *linux.IFReq) *syserr.Error {
	var (
		iface inet.Interface
		index int32
		found bool
	)

	// Find the relevant device.
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		log.Warningf("Couldn't find a network stack.")
		return syserr.ErrInvalidArgument
	}
	for index, iface = range stack.Interfaces() {
		if iface.Name == ifr.Name() {
			found = true
			break
		}
	}
	if !found {
		return syserr.ErrNoDevice
	}

	switch arg {
	case syscall.SIOCGIFINDEX:
		// Copy out the index to the data.
		usermem.ByteOrder.PutUint32(ifr.Data[:], uint32(index))

	case syscall.SIOCGIFHWADDR:
		// Copy the hardware address out.
		ifr.Data[0] = 6 // IEEE802.2 arp type.
		ifr.Data[1] = 0
		n := copy(ifr.Data[2:], iface.Addr)
		for i := 2 + n; i < len(ifr.Data); i++ {
			ifr.Data[i] = 0 // Clear padding.
		}
		usermem.ByteOrder.PutUint16(ifr.Data[:2], uint16(n))

	case syscall.SIOCGIFFLAGS:
		// TODO: Implement. For now, return only that the
		// device is up so that ifconfig prints it.
		usermem.ByteOrder.PutUint16(ifr.Data[:2], linux.IFF_UP)

	case syscall.SIOCGIFADDR:
		// Copy the IPv4 address out.
		for _, addr := range stack.InterfaceAddrs()[index] {
			// This ioctl is only compatible with AF_INET addresses.
			if addr.Family != linux.AF_INET {
				continue
			}
			copy(ifr.Data[4:8], addr.Addr)
			break
		}

	case syscall.SIOCGIFMETRIC:
		// Gets the metric of the device. As per netdevice(7), this
		// always just sets ifr_metric to 0.
		usermem.ByteOrder.PutUint32(ifr.Data[:4], 0)
	case syscall.SIOCGIFMTU:
		// Gets the MTU of the device.
		// TODO: Implement.

	case syscall.SIOCGIFMAP:
		// Gets the hardware parameters of the device.
		// TODO: Implement.

	case syscall.SIOCGIFTXQLEN:
		// Gets the transmit queue length of the device.
		// TODO: Implement.

	case syscall.SIOCGIFDSTADDR:
		// Gets the destination address of a point-to-point device.
		// TODO: Implement.

	case syscall.SIOCGIFBRDADDR:
		// Gets the broadcast address of a device.
		// TODO: Implement.

	case syscall.SIOCGIFNETMASK:
		// Gets the network mask of a device.
		for _, addr := range stack.InterfaceAddrs()[index] {
			// This ioctl is only compatible with AF_INET addresses.
			if addr.Family != linux.AF_INET {
				continue
			}
			// Populate ifr.ifr_netmask (type sockaddr).
			usermem.ByteOrder.PutUint16(ifr.Data[0:2], uint16(linux.AF_INET))
			usermem.ByteOrder.PutUint16(ifr.Data[2:4], 0)
			var mask uint32 = 0xffffffff << (32 - addr.PrefixLen)
			// Netmask is expected to be returned as a big endian
			// value.
			binary.BigEndian.PutUint32(ifr.Data[4:8], mask)
			break
		}

	default:
		// Not a valid call.
		return syserr.ErrInvalidArgument
	}

	return nil
}

// Ioctl implements fs.FileOperations.Ioctl.
func (s *SocketOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch arg := int(args[1].Int()); arg {
	case syscall.SIOCGIFFLAGS,
		syscall.SIOCGIFADDR,
		syscall.SIOCGIFBRDADDR,
		syscall.SIOCGIFDSTADDR,
		syscall.SIOCGIFHWADDR,
		syscall.SIOCGIFINDEX,
		syscall.SIOCGIFMAP,
		syscall.SIOCGIFMETRIC,
		syscall.SIOCGIFMTU,
		syscall.SIOCGIFNETMASK,
		syscall.SIOCGIFTXQLEN:

		var ifr linux.IFReq
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &ifr, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		if err := s.interfaceIoctl(ctx, io, arg, &ifr); err != nil {
			return 0, err.ToError()
		}
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), &ifr, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case syscall.SIOCGIFCONF:
		// Return a list of interface addresses or the buffer size
		// necessary to hold the list.
		var ifc linux.IFConf
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &ifc, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}

		if err := s.ifconfIoctl(ctx, io, &ifc); err != nil {
			return 0, err
		}

		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), ifc, usermem.IOOpts{
			AddressSpaceActive: true,
		})

		return 0, err
	}

	return Ioctl(ctx, s.Endpoint, io, args)
}

// ifconfIoctl populates a struct ifconf for the SIOCGIFCONF ioctl.
func (s *SocketOperations) ifconfIoctl(ctx context.Context, io usermem.IO, ifc *linux.IFConf) error {
	// If Ptr is NULL, return the necessary buffer size via Len.
	// Otherwise, write up to Len bytes starting at Ptr containing ifreq
	// structs.
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		log.Warningf("Couldn't find a network stack.")
		return syserr.ErrInvalidArgument.ToError()
	}
	if ifc.Ptr == 0 {
		ifc.Len = int32(len(stack.Interfaces())) * int32(linux.SizeOfIFReq)
		return nil
	}

	max := ifc.Len
	ifc.Len = 0
	for key, ifaceAddrs := range stack.InterfaceAddrs() {
		iface := stack.Interfaces()[key]
		for _, ifaceAddr := range ifaceAddrs {
			// Don't write past the end of the buffer.
			if ifc.Len+int32(linux.SizeOfIFReq) > max {
				break
			}
			if ifaceAddr.Family != linux.AF_INET {
				continue
			}

			// Populate ifr.ifr_addr.
			ifr := linux.IFReq{}
			ifr.SetName(iface.Name)
			usermem.ByteOrder.PutUint16(ifr.Data[0:2], uint16(ifaceAddr.Family))
			usermem.ByteOrder.PutUint16(ifr.Data[2:4], 0)
			copy(ifr.Data[4:8], ifaceAddr.Addr[:4])

			// Copy the ifr to userspace.
			dst := uintptr(ifc.Ptr) + uintptr(ifc.Len)
			ifc.Len += int32(linux.SizeOfIFReq)
			if _, err := usermem.CopyObjectOut(ctx, io, usermem.Addr(dst), ifr, usermem.IOOpts{
				AddressSpaceActive: true,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Ioctl implements fs.FileOperations.Ioctl for sockets backed by a
// commonEndpoint.
func Ioctl(ctx context.Context, ep commonEndpoint, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	// Switch on ioctl request.
	switch int(args[1].Int()) {
	case linux.TIOCINQ:
		var v tcpip.ReceiveQueueSizeOption
		if err := ep.GetSockOpt(&v); err != nil {
			return 0, syserr.TranslateNetstackError(err).ToError()
		}

		if v > math.MaxInt32 {
			v = math.MaxInt32
		}
		// Copy result to user-space.
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), int32(v), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case linux.TIOCOUTQ:
		var v tcpip.SendQueueSizeOption
		if err := ep.GetSockOpt(&v); err != nil {
			return 0, syserr.TranslateNetstackError(err).ToError()
		}

		if v > math.MaxInt32 {
			v = math.MaxInt32
		}

		// Copy result to user-space.
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), int32(v), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	}

	return 0, syserror.ENOTTY
}
