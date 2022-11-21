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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	sizeofInt32 = 4

	// sizeofSockaddr is the size in bytes of the largest sockaddr type
	// supported by this package.
	sizeofSockaddr = unix.SizeofSockaddrInet6 // sizeof(sockaddr_in6) > sizeof(sockaddr_in)

	// maxControlLen is the maximum size of a control message buffer used in a
	// recvmsg or sendmsg unix.
	maxControlLen = 1024
)

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
func (s *Socket) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return ioctl(ctx, s.fd, uio, args)
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
	n, err := dst.CopyOutFrom(ctx, reader)
	hostfd.PutReadWriterAt(reader)
	return int64(n), err
}

// PWrite implements vfs.FileDescriptionImpl.
func (s *Socket) PWrite(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.
func (s *Socket) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	writer := hostfd.GetReadWriterAt(int32(s.fd), -1, opts.Flags)
	n, err := src.CopyInTo(ctx, writer)
	hostfd.PutReadWriterAt(writer)
	return int64(n), err
}

type socketProvider struct {
	family int
}

// Socket implements socket.Provider.Socket.
func (p *socketProvider) Socket(t *kernel.Task, stypeflags linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Check that we are using the host network stack.
	stack := t.NetworkContext()
	if stack == nil {
		return nil, nil
	}
	if _, ok := stack.(*Stack); !ok {
		return nil, nil
	}

	// Only accept TCP and UDP.
	stype := stypeflags & linux.SOCK_TYPE_MASK
	switch stype {
	case unix.SOCK_STREAM:
		switch protocol {
		case 0, unix.IPPROTO_TCP:
			// ok
		default:
			return nil, nil
		}
	case unix.SOCK_DGRAM:
		switch protocol {
		case 0, unix.IPPROTO_UDP:
			// ok
		default:
			return nil, nil
		}
	default:
		return nil, nil
	}

	// Conservatively ignore all flags specified by the application and add
	// SOCK_NONBLOCK since socketOperations requires it. Pass a protocol of 0
	// to simplify the syscall filters, since 0 and IPPROTO_* are equivalent.
	fd, err := unix.Socket(p.family, int(stype)|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
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
		for syscallErr == linuxerr.ErrWouldBlock {
			if ch != nil {
				if syscallErr = t.Block(ch); syscallErr != nil {
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(waiter.ReadableEvents)
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
	case unix.SHUT_RD, unix.SHUT_WR, unix.SHUT_RDWR:
		return syserr.FromError(unix.Shutdown(s.fd, how))
	default:
		return syserr.ErrInvalidArgument
	}
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *Socket) GetSockOpt(t *kernel.Task, level int, name int, optValAddr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	if outLen < 0 {
		return nil, syserr.ErrInvalidArgument
	}

	// Only allow known and safe options.
	optlen, copyIn := getSockOptLen(t, level, name)
	switch level {
	case linux.SOL_IP:
		switch name {
		case linux.IP_TOS, linux.IP_RECVTOS, linux.IP_TTL, linux.IP_RECVTTL, linux.IP_PKTINFO, linux.IP_RECVORIGDSTADDR, linux.IP_RECVERR:
			optlen = sizeofInt32
		}
	case linux.SOL_IPV6:
		switch name {
		case linux.IPV6_TCLASS, linux.IPV6_RECVTCLASS, linux.IPV6_RECVPKTINFO, linux.IPV6_UNICAST_HOPS, linux.IPV6_MULTICAST_HOPS, linux.IPV6_RECVHOPLIMIT, linux.IPV6_RECVERR, linux.IPV6_V6ONLY, linux.IPV6_RECVORIGDSTADDR:
			optlen = sizeofInt32
		}
	case linux.SOL_SOCKET:
		switch name {
		case linux.SO_BROADCAST, linux.SO_ERROR, linux.SO_KEEPALIVE, linux.SO_SNDBUF, linux.SO_RCVBUF, linux.SO_REUSEADDR, linux.SO_TIMESTAMP:
			optlen = sizeofInt32
		case linux.SO_LINGER:
			optlen = unix.SizeofLinger
		case linux.SO_RCVTIMEO, linux.SO_SNDTIMEO:
			optlen = linux.SizeOfTimeval
		}
	case linux.SOL_TCP:
		switch name {
		case linux.TCP_NODELAY, linux.TCP_MAXSEG:
			optlen = sizeofInt32
		case linux.TCP_INFO:
			optlen = linux.SizeOfTCPInfo
			// Truncate the output buffer to outLen size.
			if optlen > outLen {
				optlen = outLen
			}
		case linux.TCP_CONGESTION:
			optlen = outLen
		}
	}

	if optlen == 0 {
		return nil, syserr.ErrProtocolNotAvailable // ENOPROTOOPT
	}
	if outLen < optlen {
		return nil, syserr.ErrInvalidArgument
	}

	opt := make([]byte, optlen)
	if copyIn {
		// This is non-intuitive as normally in getsockopt one assumes that the
		// parameter is purely an out parameter. But some custom options do require
		// copying in the optVal so we do it here only for those custom options.
		if _, err := t.CopyInBytes(optValAddr, opt); err != nil {
			return nil, syserr.FromError(err)
		}
	}
	var err error
	opt, err = getsockopt(s.fd, level, name, opt)
	if err != nil {
		return nil, syserr.FromError(err)
	}
	opt = postGetSockOpt(t, level, name, opt)
	optP := primitive.ByteSlice(opt)
	return &optP, nil
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *Socket) SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error {
	// Only allow known and safe options.
	optlen := setSockOptLen(t, level, name)
	switch level {
	case linux.SOL_IP:
		switch name {
		case linux.IP_TOS, linux.IP_RECVTOS, linux.IP_TTL, linux.IP_RECVTTL, linux.IP_PKTINFO, linux.IP_RECVORIGDSTADDR, linux.IP_RECVERR:
			optlen = sizeofInt32
		}
	case linux.SOL_IPV6:
		switch name {
		case linux.IPV6_TCLASS, linux.IPV6_RECVTCLASS, linux.IPV6_RECVPKTINFO, linux.IPV6_UNICAST_HOPS, linux.IPV6_MULTICAST_HOPS, linux.IPV6_RECVHOPLIMIT, linux.IPV6_RECVERR, linux.IPV6_V6ONLY, linux.IPV6_RECVORIGDSTADDR:
			optlen = sizeofInt32
		}
	case linux.SOL_SOCKET:
		switch name {
		case linux.SO_BROADCAST, linux.SO_SNDBUF, linux.SO_RCVBUF, linux.SO_REUSEADDR, linux.SO_TIMESTAMP:
			optlen = sizeofInt32
		}
	case linux.SOL_TCP:
		switch name {
		case linux.TCP_NODELAY, linux.TCP_INQ, linux.TCP_MAXSEG:
			optlen = sizeofInt32
		case linux.TCP_CONGESTION:
			optlen = len(opt)
		}
	}

	if optlen == 0 {
		// Pretend to accept socket options we don't understand. This seems
		// dangerous, but it's what netstack does...
		return nil
	}
	if len(opt) < optlen {
		return syserr.ErrInvalidArgument
	}
	opt = opt[:optlen]

	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s.fd), uintptr(level), uintptr(name), uintptr(firstBytePtr(opt)), uintptr(len(opt)), 0)
	if errno != 0 {
		return syserr.FromError(errno)
	}
	return nil
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

// RecvMsg implements socket.Socket.RecvMsg.
func (s *Socket) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlLen uint64) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	// Only allow known and safe flags.
	if flags&^(unix.MSG_DONTWAIT|unix.MSG_PEEK|unix.MSG_TRUNC|unix.MSG_ERRQUEUE) != 0 {
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
		for err == linuxerr.ErrWouldBlock {
			// We only expect blocking to come from the actual syscall, in which
			// case it can't have returned any data.
			if n != 0 {
				panic(fmt.Sprintf("CopyOutFrom: got (%d, %v), wanted (0, %v)", n, err, err))
			}
			if ch != nil {
				if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(waiter.ReadableEvents)
				s.EventRegister(&e)
				defer s.EventUnregister(&e)
			}
			n, err = copyToDst()
		}
	}
	if err != nil {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
	}

	var senderAddr linux.SockAddr
	if senderRequested {
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

// SendMsg implements socket.Socket.SendMsg.
func (s *Socket) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	// Only allow known and safe flags.
	if flags&^(unix.MSG_DONTWAIT|unix.MSG_EOR|unix.MSG_FASTOPEN|unix.MSG_MORE|unix.MSG_NOSIGNAL) != 0 {
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
		for err == linuxerr.ErrWouldBlock {
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
				e, ch = waiter.NewChannelEntry(waiter.WritableEvents)
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
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		socket.RegisterProvider(family, &socketProvider{family})
	}
}
