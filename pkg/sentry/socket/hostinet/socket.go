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

package hostinet

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// sizeofSockaddr is the size in bytes of the largest sockaddr type
	// supported by this package.
	sizeofSockaddr = unix.SizeofSockaddrInet6 // sizeof(sockaddr_in6) > sizeof(sockaddr_in)

	// maxControlLen is the maximum size of a control message buffer used in a
	// recvmsg or sendmsg unix.
	maxControlLen = 1024
)

// AllowedSocketType is a tuple of socket family, type, and protocol.
type AllowedSocketType struct {
	Family int
	Type   int

	// Protocol of AllowAllProtocols indicates that all protocols are
	// allowed.
	Protocol int
}

// AllowAllProtocols indicates that all protocols are allowed by the stack and
// in the syscall filters.
var AllowAllProtocols = -1

// AllowedSocketTypes are the socket types which are supported by hostinet.
// These are used to validate the arguments to socket(), and also to generate
// syscall filters.
var AllowedSocketTypes = []AllowedSocketType{
	// Family, Type, Protocol.
	{unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP},
	{unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP},
	{unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP},

	{unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP},
	{unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP},
	{unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6},
}

// AllowedRawSocketTypes are the socket types which are supported by hostinet
// with raw sockets enabled.
var AllowedRawSocketTypes = []AllowedSocketType{
	{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW},
	{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP},
	{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP},
	{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP},

	{unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW},
	{unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP},
	{unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_UDP},
	{unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6},

	// AF_PACKET do not allow Write or SendMsg.
	{unix.AF_PACKET, unix.SOCK_DGRAM, AllowAllProtocols},
	{unix.AF_PACKET, unix.SOCK_RAW, AllowAllProtocols},
}

// Socket implements socket.Socket (and by extension, vfs.FileDescriptionImpl)
// for host sockets.
//
// +stateify savable
type Socket struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD
	// We store metadata for hostinet sockets internally. Technically, we should
	// access metadata (e.g. through stat, chmod) on the host for correctness,
	// but this is not very useful for inet socket fds, which do not belong to a
	// concrete file anyway.
	vfs.DentryMetadataFileDescriptionImpl
	socket.SendReceiveTimeout

	family   int            // Read-only.
	stype    linux.SockType // Read-only.
	protocol int            // Read-only.
	queue    waiter.Queue

	// fd is the host socket fd. It must have O_NONBLOCK, so that operations
	// will return EWOULDBLOCK instead of blocking on the host. This allows us to
	// handle blocking behavior independently in the sentry.
	fd int

	// recvClosed indicates that the socket has been shutdown for reading
	// (SHUT_RD or SHUT_RDWR).
	recvClosed atomicbitops.Bool
}

var _ = socket.Socket(&Socket{})

func newSocket(t *kernel.Task, family int, stype linux.SockType, protocol int, fd int, flags uint32) (*vfs.FileDescription, *syserr.Error) {
	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t, mnt)
	defer d.DecRef(t)

	s := &Socket{
		family:   family,
		stype:    stype,
		protocol: protocol,
		fd:       fd,
	}
	s.LockFD.Init(&vfs.FileLocks{})
	if err := fdnotifier.AddFD(int32(fd), &s.queue); err != nil {
		return nil, syserr.FromError(err)
	}
	vfsfd := &s.vfsfd
	if err := vfsfd.Init(s, linux.O_RDWR|(flags&linux.O_NONBLOCK), mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		fdnotifier.RemoveFD(int32(s.fd))
		return nil, syserr.FromError(err)
	}
	return vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (s *Socket) Release(ctx context.Context) {
	kernel.KernelFromContext(ctx).DeleteSocket(&s.vfsfd)
	fdnotifier.RemoveFD(int32(s.fd))
	_ = unix.Close(s.fd)
}

// Epollable implements FileDescriptionImpl.Epollable.
func (s *Socket) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.
func (s *Socket) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return ioctl(ctx, s.fd, uio, sysno, args)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (s *Socket) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Read implements vfs.FileDescriptionImpl.
func (s *Socket) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	reader := hostfd.GetReadWriterAt(int32(s.fd), -1, opts.Flags)
	defer hostfd.PutReadWriterAt(reader)
	n, err := dst.CopyOutFrom(ctx, reader)
	return int64(n), err
}

// PWrite implements vfs.FileDescriptionImpl.
func (s *Socket) PWrite(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.
func (s *Socket) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if s.family == linux.AF_PACKET {
		// Don't allow Write for AF_PACKET.
		return 0, linuxerr.EACCES
	}

	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	writer := hostfd.GetReadWriterAt(int32(s.fd), -1, opts.Flags)
	defer hostfd.PutReadWriterAt(writer)
	n, err := src.CopyInTo(ctx, writer)
	return int64(n), err
}

type socketProvider struct {
	family int
}

// Socket implements socket.Provider.Socket.
func (p *socketProvider) Socket(t *kernel.Task, stypeflags linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Check that we are using the host network stack.
	netCtx := t.NetworkContext()
	if netCtx == nil {
		return nil, nil
	}
	stack, ok := netCtx.(*Stack)
	if !ok {
		return nil, nil
	}

	stype := stypeflags & linux.SOCK_TYPE_MASK

	// Raw and packet sockets require CAP_NET_RAW.
	if stype == linux.SOCK_RAW || p.family == linux.AF_PACKET {
		if creds := auth.CredentialsFromContext(t); !creds.HasCapability(linux.CAP_NET_RAW) {
			return nil, syserr.ErrNotPermitted
		}
	}

	// Convert generic IPPROTO_IP protocol to the actual protocol depending
	// on family and type.
	if protocol == linux.IPPROTO_IP && (p.family == linux.AF_INET || p.family == linux.AF_INET6) {
		switch stype {
		case linux.SOCK_STREAM:
			protocol = linux.IPPROTO_TCP
		case linux.SOCK_DGRAM:
			protocol = linux.IPPROTO_UDP
		}
	}

	// Validate the socket based on family, type, and protocol.
	var supported bool
	for _, allowed := range stack.allowedSocketTypes {
		isAllowedFamily := p.family == allowed.Family
		isAllowedType := int(stype) == allowed.Type
		isAllowedProtocol := protocol == allowed.Protocol || allowed.Protocol == AllowAllProtocols
		if isAllowedFamily && isAllowedType && isAllowedProtocol {
			supported = true
			break
		}
	}
	if !supported {
		// Return nil error here to give other socket providers a
		// chance to create this socket.
		return nil, nil
	}

	// Conservatively ignore all flags specified by the application and add
	// SOCK_NONBLOCK since socketOperations requires it.
	st := int(stype) | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC
	fd, err := unix.Socket(p.family, st, protocol)
	if err != nil {
		return nil, syserr.FromError(err)
	}
	return newSocket(t, p.family, stype, protocol, fd, uint32(stypeflags&unix.SOCK_NONBLOCK))
}

// Pair implements socket.Provider.Pair.
func (p *socketProvider) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	// Not supported by AF_INET/AF_INET6.
	return nil, nil, nil
}

// Readiness implements waiter.Waitable.Readiness.
func (s *Socket) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(int32(s.fd), mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *Socket) EventRegister(e *waiter.Entry) error {
	s.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(int32(s.fd)); err != nil {
		s.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *Socket) EventUnregister(e *waiter.Entry) {
	s.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(int32(s.fd)); err != nil {
		panic(err)
	}
}

// Connect implements socket.Socket.Connect.
func (s *Socket) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	if len(sockaddr) > sizeofSockaddr {
		sockaddr = sockaddr[:sizeofSockaddr]
	}

	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(s.fd), uintptr(firstBytePtr(sockaddr)), uintptr(len(sockaddr)))
	if errno == 0 {
		return nil
	}
	// The host socket is always non-blocking, so we expect connect to
	// return EINPROGRESS. If we are emulating a blocking socket, we will
	// wait for the connect to complete below.
	// But if we are not emulating a blocking socket, or if we got some
	// other error, then return it now.
	if errno != unix.EINPROGRESS || !blocking {
		return syserr.FromError(translateIOSyscallError(errno))
	}

	// "EINPROGRESS: The socket is nonblocking and the connection cannot be
	// completed immediately. It is possible to select(2) or poll(2) for
	// completion by selecting the socket for writing. After select(2)
	// indicates writability, use getsockopt(2) to read the SO_ERROR option at
	// level SOL-SOCKET to determine whether connect() completed successfully
	// (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual error
	// codes listed here, explaining the reason for the failure)." - connect(2)
	writableMask := waiter.WritableEvents
	e, ch := waiter.NewChannelEntry(writableMask)
	s.EventRegister(&e)
	defer s.EventUnregister(&e)
	if s.Readiness(writableMask)&writableMask == 0 {
		if err := t.Block(ch); err != nil {
			return syserr.FromError(err)
		}
	}

	val, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return syserr.FromError(err)
	}
	if val != 0 {
		return syserr.FromError(unix.Errno(uintptr(val)))
	}

	// It seems like we are all good now, but Linux has left the socket
	// state as CONNECTING (not CONNECTED). This is a strange quirk of
	// non-blocking sockets. See tcp_finish_connect() which sets tcp state
	// but not socket state.
	//
	// Sockets in the CONNECTING state can call connect() a second time,
	// whereas CONNECTED sockets will reject the second connect() call.
	// Because we are emulating a blocking socket, we want a subsequent
	// connect() call to fail. So we must kick Linux to update the socket
	// to state CONNECTED, which we can do by calling connect() a second
	// time ourselves.
	_, _, errno = unix.Syscall(unix.SYS_CONNECT, uintptr(s.fd), uintptr(firstBytePtr(sockaddr)), uintptr(len(sockaddr)))
	if errno != 0 && errno != unix.EALREADY {
		return syserr.FromError(translateIOSyscallError(errno))
	}
	return nil
}

// Accept implements socket.Socket.Accept.
func (s *Socket) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	var peerAddr linux.SockAddr
	var peerAddrBuf []byte
	var peerAddrlen uint32
	var peerAddrPtr *byte
	var peerAddrlenPtr *uint32
	if peerRequested {
		peerAddrBuf = make([]byte, sizeofSockaddr)
		peerAddrlen = uint32(len(peerAddrBuf))
		peerAddrPtr = &peerAddrBuf[0]
		peerAddrlenPtr = &peerAddrlen
	}

	// Conservatively ignore all flags specified by the application and add
	// SOCK_NONBLOCK since socketOpsCommon requires it.
	fd, syscallErr := accept4(s.fd, peerAddrPtr, peerAddrlenPtr, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
	if blocking {
		var ch chan struct{}
		for linuxerr.Equals(linuxerr.ErrWouldBlock, syscallErr) {
			if ch != nil {
				if syscallErr = t.Block(ch); syscallErr != nil {
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp | waiter.EventErr)
				s.EventRegister(&e)
				defer s.EventUnregister(&e)
			}
			fd, syscallErr = accept4(s.fd, peerAddrPtr, peerAddrlenPtr, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		}
	}

	if peerRequested {
		peerAddr = socket.UnmarshalSockAddr(s.family, peerAddrBuf[:peerAddrlen])
	}
	if syscallErr != nil {
		return 0, peerAddr, peerAddrlen, syserr.FromError(syscallErr)
	}

	var (
		kfd  int32
		kerr error
	)
	f, err := newSocket(t, s.family, s.stype, s.protocol, fd, uint32(flags&unix.SOCK_NONBLOCK))
	if err != nil {
		_ = unix.Close(fd)
		return 0, nil, 0, err
	}
	defer f.DecRef(t)

	kfd, kerr = t.NewFDFrom(0, f, kernel.FDFlags{
		CloseOnExec: flags&unix.SOCK_CLOEXEC != 0,
	})
	t.Kernel().RecordSocket(f)

	return kfd, peerAddr, peerAddrlen, syserr.FromError(kerr)
}

// Bind implements socket.Socket.Bind.
func (s *Socket) Bind(_ *kernel.Task, sockaddr []byte) *syserr.Error {
	if len(sockaddr) > sizeofSockaddr {
		sockaddr = sockaddr[:sizeofSockaddr]
	}

	_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(s.fd), uintptr(firstBytePtr(sockaddr)), uintptr(len(sockaddr)))
	if errno != 0 {
		return syserr.FromError(errno)
	}
	return nil
}

// Listen implements socket.Socket.Listen.
func (s *Socket) Listen(_ *kernel.Task, backlog int) *syserr.Error {
	return syserr.FromError(unix.Listen(s.fd, backlog))
}

// Shutdown implements socket.Socket.Shutdown.
func (s *Socket) Shutdown(_ *kernel.Task, how int) *syserr.Error {
	switch how {
	case unix.SHUT_RD, unix.SHUT_RDWR:
		// Mark the socket as closed for reading.
		s.recvClosed.Store(true)
		fallthrough
	case unix.SHUT_WR:
		return syserr.FromError(unix.Shutdown(s.fd, how))
	default:
		return syserr.ErrInvalidArgument
	}
}

func (s *Socket) recvMsgFromHost(iovs []unix.Iovec, flags int, senderRequested bool, controlLen uint64) (uint64, int, []byte, []byte, error) {
	// We always do a non-blocking recv*().
	sysflags := flags | unix.MSG_DONTWAIT

	msg := unix.Msghdr{}
	if len(iovs) > 0 {
		msg.Iov = &iovs[0]
		msg.Iovlen = uint64(len(iovs))
	}
	var senderAddrBuf []byte
	if senderRequested {
		senderAddrBuf = make([]byte, sizeofSockaddr)
		msg.Name = &senderAddrBuf[0]
		msg.Namelen = uint32(sizeofSockaddr)
	}
	var controlBuf []byte
	if controlLen > 0 {
		if controlLen > maxControlLen {
			controlLen = maxControlLen
		}
		controlBuf = make([]byte, controlLen)
		msg.Control = &controlBuf[0]
		msg.Controllen = controlLen
	}
	n, err := recvmsg(s.fd, &msg, sysflags)
	if err != nil {
		return 0 /* n */, 0 /* mFlags */, nil /* senderAddrBuf */, nil /* controlBuf */, err
	}
	return n, int(msg.Flags), senderAddrBuf[:msg.Namelen], controlBuf[:msg.Controllen], err
}

const allowedRecvMsgFlags = unix.MSG_CTRUNC |
	unix.MSG_DONTWAIT |
	unix.MSG_ERRQUEUE |
	unix.MSG_OOB |
	unix.MSG_PEEK |
	unix.MSG_TRUNC |
	unix.MSG_WAITALL

// RecvMsg implements socket.Socket.RecvMsg.
func (s *Socket) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlLen uint64) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	// Only allow known and safe flags.
	if flags&^allowedRecvMsgFlags != 0 {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrInvalidArgument
	}

	var senderAddrBuf []byte
	var controlBuf []byte
	var msgFlags int
	copyToDst := func() (int64, error) {
		var n uint64
		var err error
		if dst.NumBytes() == 0 {
			// We want to make the recvmsg(2) call to the host even if dst is empty
			// to fetch control messages, sender address or errors if any occur.
			n, msgFlags, senderAddrBuf, controlBuf, err = s.recvMsgFromHost(nil, flags, senderRequested, controlLen)
			return int64(n), err
		}

		recvmsgToBlocks := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
			// Refuse to do anything if any part of dst.Addrs was unusable.
			if uint64(dst.NumBytes()) != dsts.NumBytes() {
				return 0, nil
			}
			if dsts.IsEmpty() {
				return 0, nil
			}

			n, msgFlags, senderAddrBuf, controlBuf, err = s.recvMsgFromHost(safemem.IovecsFromBlockSeq(dsts), flags, senderRequested, controlLen)
			return n, err
		})
		return dst.CopyOutFrom(t, recvmsgToBlocks)
	}

	var ch chan struct{}
	n, err := copyToDst()

	// recv*(MSG_ERRQUEUE) never blocks, even without MSG_DONTWAIT.
	if flags&(unix.MSG_DONTWAIT|unix.MSG_ERRQUEUE) == 0 {
		for linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			// We only expect blocking to come from the actual syscall, in which
			// case it can't have returned any data.
			if n != 0 {
				panic(fmt.Sprintf("CopyOutFrom: got (%d, %v), wanted (0, %v)", n, err, err))
			}
			// Are we closed for reading? No sense in trying to read if so.
			if s.recvClosed.Load() {
				break
			}
			if ch != nil {
				if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
					if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
						err = linuxerr.ErrWouldBlock
					}
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventRdHUp | waiter.EventHUp | waiter.EventErr)
				s.EventRegister(&e)
				defer s.EventUnregister(&e)
			}
			n, err = copyToDst()
		}
	}
	if err != nil {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
	}

	// In some circumstances (like MSG_PEEK specified), the sender address
	// field is purposefully ignored. recvMsgFromHost will return an empty
	// senderAddrBuf in those cases.
	var senderAddr linux.SockAddr
	if senderRequested && len(senderAddrBuf) > 0 {
		senderAddr = socket.UnmarshalSockAddr(s.family, senderAddrBuf)
	}

	unixControlMessages, err := unix.ParseSocketControlMessage(controlBuf)
	if err != nil {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
	}
	return int(n), msgFlags, senderAddr, uint32(len(senderAddrBuf)), parseUnixControlMessages(unixControlMessages), nil
}

func parseUnixControlMessages(unixControlMessages []unix.SocketControlMessage) socket.ControlMessages {
	controlMessages := socket.ControlMessages{}
	for _, unixCmsg := range unixControlMessages {
		switch unixCmsg.Header.Level {
		case linux.SOL_SOCKET:
			switch unixCmsg.Header.Type {
			case linux.SO_TIMESTAMP:
				controlMessages.IP.HasTimestamp = true
				ts := linux.Timeval{}
				ts.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.Timestamp = ts.ToTime()
			}

		case linux.SOL_IP:
			switch unixCmsg.Header.Type {
			case linux.IP_TOS:
				controlMessages.IP.HasTOS = true
				var tos primitive.Uint8
				tos.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.TOS = uint8(tos)

			case linux.IP_TTL:
				controlMessages.IP.HasTTL = true
				var ttl primitive.Uint32
				ttl.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.TTL = uint32(ttl)

			case linux.IP_PKTINFO:
				controlMessages.IP.HasIPPacketInfo = true
				var packetInfo linux.ControlMessageIPPacketInfo
				packetInfo.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.PacketInfo = packetInfo

			case linux.IP_RECVORIGDSTADDR:
				var addr linux.SockAddrInet
				addr.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.OriginalDstAddress = &addr

			case unix.IP_RECVERR:
				var errCmsg linux.SockErrCMsgIPv4
				errCmsg.UnmarshalBytes(unixCmsg.Data)
				controlMessages.IP.SockErr = &errCmsg
			}

		case linux.SOL_IPV6:
			switch unixCmsg.Header.Type {
			case linux.IPV6_TCLASS:
				controlMessages.IP.HasTClass = true
				var tclass primitive.Uint32
				tclass.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.TClass = uint32(tclass)

			case linux.IPV6_PKTINFO:
				controlMessages.IP.HasIPv6PacketInfo = true
				var packetInfo linux.ControlMessageIPv6PacketInfo
				packetInfo.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.IPv6PacketInfo = packetInfo

			case linux.IPV6_HOPLIMIT:
				controlMessages.IP.HasHopLimit = true
				var hoplimit primitive.Uint32
				hoplimit.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.HopLimit = uint32(hoplimit)

			case linux.IPV6_RECVORIGDSTADDR:
				var addr linux.SockAddrInet6
				addr.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.OriginalDstAddress = &addr

			case unix.IPV6_RECVERR:
				var errCmsg linux.SockErrCMsgIPv6
				errCmsg.UnmarshalBytes(unixCmsg.Data)
				controlMessages.IP.SockErr = &errCmsg
			}

		case linux.SOL_TCP:
			switch unixCmsg.Header.Type {
			case linux.TCP_INQ:
				controlMessages.IP.HasInq = true
				var inq primitive.Int32
				inq.UnmarshalUnsafe(unixCmsg.Data)
				controlMessages.IP.Inq = int32(inq)
			}
		}
	}
	return controlMessages
}

const allowedSendMsgFlags = unix.MSG_DONTWAIT |
	unix.MSG_EOR |
	unix.MSG_FASTOPEN |
	unix.MSG_MORE |
	unix.MSG_NOSIGNAL |
	unix.MSG_OOB

// SendMsg implements socket.Socket.SendMsg.
func (s *Socket) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	if s.family == linux.AF_PACKET {
		// Don't allow SendMesg for AF_PACKET.
		return 0, syserr.ErrPermissionDenied
	}

	// Only allow known and safe flags.
	if flags&^allowedSendMsgFlags != 0 {
		return 0, syserr.ErrInvalidArgument
	}

	// If the src is zero-length, call SENDTO directly with a null buffer in
	// order to generate poll/epoll notifications.
	if src.NumBytes() == 0 {
		sysflags := flags | unix.MSG_DONTWAIT
		n, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(s.fd), 0, 0, uintptr(sysflags), uintptr(firstBytePtr(to)), uintptr(len(to)))
		if errno != 0 {
			return 0, syserr.FromError(errno)
		}
		return int(n), nil
	}

	space := uint64(control.CmsgsSpace(t, controlMessages))
	if space > maxControlLen {
		space = maxControlLen
	}
	controlBuf := make([]byte, 0, space)
	// PackControlMessages will append up to space bytes to controlBuf.
	controlBuf = control.PackControlMessages(t, controlMessages, controlBuf)

	sendmsgFromBlocks := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		// Refuse to do anything if any part of src.Addrs was unusable.
		if uint64(src.NumBytes()) != srcs.NumBytes() {
			return 0, nil
		}
		if srcs.IsEmpty() && len(controlBuf) == 0 {
			return 0, nil
		}

		// We always do a non-blocking send*().
		sysflags := flags | unix.MSG_DONTWAIT

		if srcs.NumBlocks() == 1 && len(controlBuf) == 0 {
			// Skip allocating []unix.Iovec.
			src := srcs.Head()
			n, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(s.fd), src.Addr(), uintptr(src.Len()), uintptr(sysflags), uintptr(firstBytePtr(to)), uintptr(len(to)))
			if errno != 0 {
				return 0, translateIOSyscallError(errno)
			}
			return uint64(n), nil
		}

		iovs := safemem.IovecsFromBlockSeq(srcs)
		msg := unix.Msghdr{
			Iov:    &iovs[0],
			Iovlen: uint64(len(iovs)),
		}
		if len(to) != 0 {
			msg.Name = &to[0]
			msg.Namelen = uint32(len(to))
		}
		if len(controlBuf) != 0 {
			msg.Control = &controlBuf[0]
			msg.Controllen = uint64(len(controlBuf))
		}
		return sendmsg(s.fd, &msg, sysflags)
	})

	var ch chan struct{}
	n, err := src.CopyInTo(t, sendmsgFromBlocks)
	if flags&unix.MSG_DONTWAIT == 0 {
		for linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			// We only expect blocking to come from the actual syscall, in which
			// case it can't have returned any data.
			if n != 0 {
				panic(fmt.Sprintf("CopyInTo: got (%d, %v), wanted (0, %v)", n, err, err))
			}
			if ch != nil {
				if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
					if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
						err = linuxerr.ErrWouldBlock
					}
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
				s.EventRegister(&e)
				defer s.EventUnregister(&e)
			}
			n, err = src.CopyInTo(t, sendmsgFromBlocks)
		}
	}

	return int(n), syserr.FromError(err)
}

func translateIOSyscallError(err error) error {
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
		return linuxerr.ErrWouldBlock
	}
	return err
}

// State implements socket.Socket.State.
func (s *Socket) State() uint32 {
	info := linux.TCPInfo{}
	buf := make([]byte, linux.SizeOfTCPInfo)
	var err error
	buf, err = getsockopt(s.fd, unix.SOL_TCP, unix.TCP_INFO, buf)
	if err != nil {
		if err != unix.ENOPROTOOPT {
			log.Warningf("Failed to get TCP socket info from %+v: %v", s, err)
		}
		// For non-TCP sockets, silently ignore the failure.
		return 0
	}
	if len(buf) != linux.SizeOfTCPInfo {
		// Unmarshal below will panic if getsockopt returns a buffer of
		// unexpected size.
		log.Warningf("Failed to get TCP socket info from %+v: getsockopt(2) returned %d bytes, expecting %d bytes.", s, len(buf), linux.SizeOfTCPInfo)
		return 0
	}

	info.UnmarshalUnsafe(buf[:info.SizeBytes()])
	return uint32(info.State)
}

// Type implements socket.Socket.Type.
func (s *Socket) Type() (family int, skType linux.SockType, protocol int) {
	return s.family, s.stype, s.protocol
}

func init() {
	// Register all families in AllowedSocketTypes and AllowedRawSocket
	// types. If we don't allow raw sockets, they will be rejected in the
	// Socket call.
	registered := make(map[int]struct{})
	for _, sockType := range append(AllowedSocketTypes, AllowedRawSocketTypes...) {
		fam := sockType.Family
		if _, ok := registered[fam]; ok {
			continue
		}
		socket.RegisterProvider(fam, &socketProvider{fam})
		registered[fam] = struct{}{}
	}
}
