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
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	sizeofInt32 = 4

	// sizeofSockaddr is the size in bytes of the largest sockaddr type
	// supported by this package.
	sizeofSockaddr = syscall.SizeofSockaddrInet6 // sizeof(sockaddr_in6) > sizeof(sockaddr_in)

	// maxControlLen is the maximum size of a control message buffer used in a
	// recvmsg or sendmsg syscall.
	maxControlLen = 1024
)

// LINT.IfChange

// socketOperations implements fs.FileOperations and socket.Socket for a socket
// implemented using a host socket.
type socketOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	socketOpsCommon
}

// socketOpsCommon contains the socket operations common to VFS1 and VFS2.
//
// +stateify savable
type socketOpsCommon struct {
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

var _ = socket.Socket(&socketOperations{})

func newSocketFile(ctx context.Context, family int, stype linux.SockType, protocol int, fd int, nonblock bool) (*fs.File, *syserr.Error) {
	s := &socketOperations{
		socketOpsCommon: socketOpsCommon{
			family:   family,
			stype:    stype,
			protocol: protocol,
			fd:       fd,
		},
	}
	if err := fdnotifier.AddFD(int32(fd), &s.queue); err != nil {
		return nil, syserr.FromError(err)
	}
	dirent := socket.NewDirent(ctx, socketDevice)
	defer dirent.DecRef(ctx)
	return fs.NewFile(ctx, dirent, fs.FileFlags{NonBlocking: nonblock, Read: true, Write: true, NonSeekable: true}, s), nil
}

// Release implements fs.FileOperations.Release.
func (s *socketOpsCommon) Release(context.Context) {
	fdnotifier.RemoveFD(int32(s.fd))
	syscall.Close(s.fd)
}

// Readiness implements waiter.Waitable.Readiness.
func (s *socketOpsCommon) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(int32(s.fd), mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *socketOpsCommon) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.queue.EventRegister(e, mask)
	fdnotifier.UpdateFD(int32(s.fd))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *socketOpsCommon) EventUnregister(e *waiter.Entry) {
	s.queue.EventUnregister(e)
	fdnotifier.UpdateFD(int32(s.fd))
}

// Ioctl implements fs.FileOperations.Ioctl.
func (s *socketOperations) Ioctl(ctx context.Context, _ *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return ioctl(ctx, s.fd, io, args)
}

// Read implements fs.FileOperations.Read.
func (s *socketOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	n, err := dst.CopyOutFrom(ctx, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		// Refuse to do anything if any part of dst.Addrs was unusable.
		if uint64(dst.NumBytes()) != dsts.NumBytes() {
			return 0, nil
		}
		if dsts.IsEmpty() {
			return 0, nil
		}
		if dsts.NumBlocks() == 1 {
			// Skip allocating []syscall.Iovec.
			n, err := syscall.Read(s.fd, dsts.Head().ToSlice())
			if err != nil {
				return 0, translateIOSyscallError(err)
			}
			return uint64(n), nil
		}
		return readv(s.fd, safemem.IovecsFromBlockSeq(dsts))
	}))
	return int64(n), err
}

// Write implements fs.FileOperations.Write.
func (s *socketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	n, err := src.CopyInTo(ctx, safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		// Refuse to do anything if any part of src.Addrs was unusable.
		if uint64(src.NumBytes()) != srcs.NumBytes() {
			return 0, nil
		}
		if srcs.IsEmpty() {
			return 0, nil
		}
		if srcs.NumBlocks() == 1 {
			// Skip allocating []syscall.Iovec.
			n, err := syscall.Write(s.fd, srcs.Head().ToSlice())
			if err != nil {
				return 0, translateIOSyscallError(err)
			}
			return uint64(n), nil
		}
		return writev(s.fd, safemem.IovecsFromBlockSeq(srcs))
	}))
	return int64(n), err
}

// Connect implements socket.Socket.Connect.
func (s *socketOpsCommon) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	if len(sockaddr) > sizeofSockaddr {
		sockaddr = sockaddr[:sizeofSockaddr]
	}

	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(s.fd), uintptr(firstBytePtr(sockaddr)), uintptr(len(sockaddr)))

	if errno == 0 {
		return nil
	}
	if errno != syscall.EINPROGRESS || !blocking {
		return syserr.FromError(translateIOSyscallError(errno))
	}

	// "EINPROGRESS: The socket is nonblocking and the connection cannot be
	// completed immediately. It is possible to select(2) or poll(2) for
	// completion by selecting the socket for writing. After select(2)
	// indicates writability, use getsockopt(2) to read the SO_ERROR option at
	// level SOL-SOCKET to determine whether connect() completed successfully
	// (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual error
	// codes listed here, explaining the reason for the failure)." - connect(2)
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)
	if s.Readiness(waiter.EventOut)&waiter.EventOut == 0 {
		if err := t.Block(ch); err != nil {
			return syserr.FromError(err)
		}
	}
	val, err := syscall.GetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return syserr.FromError(err)
	}
	if val != 0 {
		return syserr.FromError(syscall.Errno(uintptr(val)))
	}
	return nil
}

// Accept implements socket.Socket.Accept.
func (s *socketOpsCommon) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
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
	fd, syscallErr := accept4(s.fd, peerAddrPtr, peerAddrlenPtr, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
	if blocking {
		var ch chan struct{}
		for syscallErr == syserror.ErrWouldBlock {
			if ch != nil {
				if syscallErr = t.Block(ch); syscallErr != nil {
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(nil)
				s.EventRegister(&e, waiter.EventIn)
				defer s.EventUnregister(&e)
			}
			fd, syscallErr = accept4(s.fd, peerAddrPtr, peerAddrlenPtr, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
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
	if kernel.VFS2Enabled {
		f, err := newVFS2Socket(t, s.family, s.stype, s.protocol, fd, uint32(flags&syscall.SOCK_NONBLOCK))
		if err != nil {
			syscall.Close(fd)
			return 0, nil, 0, err
		}
		defer f.DecRef(t)

		kfd, kerr = t.NewFDFromVFS2(0, f, kernel.FDFlags{
			CloseOnExec: flags&syscall.SOCK_CLOEXEC != 0,
		})
		t.Kernel().RecordSocketVFS2(f)
	} else {
		f, err := newSocketFile(t, s.family, s.stype, s.protocol, fd, flags&syscall.SOCK_NONBLOCK != 0)
		if err != nil {
			syscall.Close(fd)
			return 0, nil, 0, err
		}
		defer f.DecRef(t)

		kfd, kerr = t.NewFDFrom(0, f, kernel.FDFlags{
			CloseOnExec: flags&syscall.SOCK_CLOEXEC != 0,
		})
		t.Kernel().RecordSocket(f)
	}

	return kfd, peerAddr, peerAddrlen, syserr.FromError(kerr)
}

// Bind implements socket.Socket.Bind.
func (s *socketOpsCommon) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	if len(sockaddr) > sizeofSockaddr {
		sockaddr = sockaddr[:sizeofSockaddr]
	}

	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(s.fd), uintptr(firstBytePtr(sockaddr)), uintptr(len(sockaddr)))
	if errno != 0 {
		return syserr.FromError(errno)
	}
	return nil
}

// Listen implements socket.Socket.Listen.
func (s *socketOpsCommon) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return syserr.FromError(syscall.Listen(s.fd, backlog))
}

// Shutdown implements socket.Socket.Shutdown.
func (s *socketOpsCommon) Shutdown(t *kernel.Task, how int) *syserr.Error {
	switch how {
	case syscall.SHUT_RD, syscall.SHUT_WR, syscall.SHUT_RDWR:
		return syserr.FromError(syscall.Shutdown(s.fd, how))
	default:
		return syserr.ErrInvalidArgument
	}
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *socketOpsCommon) GetSockOpt(t *kernel.Task, level int, name int, outPtr usermem.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	if outLen < 0 {
		return nil, syserr.ErrInvalidArgument
	}

	// Only allow known and safe options.
	optlen := getSockOptLen(t, level, name)
	switch level {
	case linux.SOL_IP:
		switch name {
		case linux.IP_TOS, linux.IP_RECVTOS, linux.IP_PKTINFO, linux.IP_RECVORIGDSTADDR:
			optlen = sizeofInt32
		}
	case linux.SOL_IPV6:
		switch name {
		case linux.IPV6_TCLASS, linux.IPV6_RECVTCLASS, linux.IPV6_V6ONLY, linux.IPV6_RECVORIGDSTADDR:
			optlen = sizeofInt32
		}
	case linux.SOL_SOCKET:
		switch name {
		case linux.SO_ERROR, linux.SO_KEEPALIVE, linux.SO_SNDBUF, linux.SO_RCVBUF, linux.SO_REUSEADDR, linux.SO_TIMESTAMP:
			optlen = sizeofInt32
		case linux.SO_LINGER:
			optlen = syscall.SizeofLinger
		}
	case linux.SOL_TCP:
		switch name {
		case linux.TCP_NODELAY:
			optlen = sizeofInt32
		case linux.TCP_INFO:
			optlen = int(linux.SizeOfTCPInfo)
		}
	}

	if optlen == 0 {
		return nil, syserr.ErrProtocolNotAvailable // ENOPROTOOPT
	}
	if outLen < optlen {
		return nil, syserr.ErrInvalidArgument
	}

	opt, err := getsockopt(s.fd, level, name, optlen)
	if err != nil {
		return nil, syserr.FromError(err)
	}
	optP := primitive.ByteSlice(opt)
	return &optP, nil
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *socketOpsCommon) SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error {
	// Only allow known and safe options.
	optlen := setSockOptLen(t, level, name)
	switch level {
	case linux.SOL_IP:
		switch name {
		case linux.IP_TOS, linux.IP_RECVTOS, linux.IP_RECVORIGDSTADDR:
			optlen = sizeofInt32
		case linux.IP_PKTINFO:
			optlen = linux.SizeOfControlMessageIPPacketInfo
		}
	case linux.SOL_IPV6:
		switch name {
		case linux.IPV6_TCLASS, linux.IPV6_RECVTCLASS, linux.IPV6_V6ONLY, linux.IPV6_RECVORIGDSTADDR:
			optlen = sizeofInt32
		}
	case linux.SOL_SOCKET:
		switch name {
		case linux.SO_SNDBUF, linux.SO_RCVBUF, linux.SO_REUSEADDR, linux.SO_TIMESTAMP:
			optlen = sizeofInt32
		}
	case linux.SOL_TCP:
		switch name {
		case linux.TCP_NODELAY, linux.TCP_INQ:
			optlen = sizeofInt32
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

	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s.fd), uintptr(level), uintptr(name), uintptr(firstBytePtr(opt)), uintptr(len(opt)), 0)
	if errno != 0 {
		return syserr.FromError(errno)
	}
	return nil
}

// RecvMsg implements socket.Socket.RecvMsg.
func (s *socketOpsCommon) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlLen uint64) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	// Only allow known and safe flags.
	//
	// FIXME(jamieliu): We can't support MSG_ERRQUEUE because it uses ancillary
	// messages that gvisor/pkg/tcpip/transport/unix doesn't understand. Kill the
	// Socket interface's dependence on netstack.
	if flags&^(syscall.MSG_DONTWAIT|syscall.MSG_PEEK|syscall.MSG_TRUNC) != 0 {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrInvalidArgument
	}

	var senderAddr linux.SockAddr
	var senderAddrBuf []byte
	if senderRequested {
		senderAddrBuf = make([]byte, sizeofSockaddr)
	}

	var controlBuf []byte
	var msgFlags int

	recvmsgToBlocks := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		// Refuse to do anything if any part of dst.Addrs was unusable.
		if uint64(dst.NumBytes()) != dsts.NumBytes() {
			return 0, nil
		}
		if dsts.IsEmpty() {
			return 0, nil
		}

		// We always do a non-blocking recv*().
		sysflags := flags | syscall.MSG_DONTWAIT

		iovs := safemem.IovecsFromBlockSeq(dsts)
		msg := syscall.Msghdr{
			Iov:    &iovs[0],
			Iovlen: uint64(len(iovs)),
		}
		if len(senderAddrBuf) != 0 {
			msg.Name = &senderAddrBuf[0]
			msg.Namelen = uint32(len(senderAddrBuf))
		}
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
			return 0, err
		}
		senderAddrBuf = senderAddrBuf[:msg.Namelen]
		msgFlags = int(msg.Flags)
		controlLen = uint64(msg.Controllen)
		return n, nil
	})

	var ch chan struct{}
	n, err := dst.CopyOutFrom(t, recvmsgToBlocks)
	if flags&syscall.MSG_DONTWAIT == 0 {
		for err == syserror.ErrWouldBlock {
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
				e, ch = waiter.NewChannelEntry(nil)
				s.EventRegister(&e, waiter.EventIn)
				defer s.EventUnregister(&e)
			}
			n, err = dst.CopyOutFrom(t, recvmsgToBlocks)
		}
	}
	if err != nil {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
	}

	if senderRequested {
		senderAddr = socket.UnmarshalSockAddr(s.family, senderAddrBuf)
	}

	unixControlMessages, err := unix.ParseSocketControlMessage(controlBuf[:controlLen])
	if err != nil {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
	}

	controlMessages := socket.ControlMessages{}
	for _, unixCmsg := range unixControlMessages {
		switch unixCmsg.Header.Level {
		case linux.SOL_SOCKET:
			switch unixCmsg.Header.Type {
			case linux.SO_TIMESTAMP:
				controlMessages.IP.HasTimestamp = true
				binary.Unmarshal(unixCmsg.Data[:linux.SizeOfTimeval], usermem.ByteOrder, &controlMessages.IP.Timestamp)
			}

		case linux.SOL_IP:
			switch unixCmsg.Header.Type {
			case linux.IP_TOS:
				controlMessages.IP.HasTOS = true
				binary.Unmarshal(unixCmsg.Data[:linux.SizeOfControlMessageTOS], usermem.ByteOrder, &controlMessages.IP.TOS)

			case linux.IP_PKTINFO:
				controlMessages.IP.HasIPPacketInfo = true
				var packetInfo linux.ControlMessageIPPacketInfo
				binary.Unmarshal(unixCmsg.Data[:linux.SizeOfControlMessageIPPacketInfo], usermem.ByteOrder, &packetInfo)
				controlMessages.IP.PacketInfo = packetInfo

			case linux.IP_RECVORIGDSTADDR:
				var addr linux.SockAddrInet
				binary.Unmarshal(unixCmsg.Data[:addr.SizeBytes()], usermem.ByteOrder, &addr)
				controlMessages.IP.OriginalDstAddress = &addr
			}

		case linux.SOL_IPV6:
			switch unixCmsg.Header.Type {
			case linux.IPV6_TCLASS:
				controlMessages.IP.HasTClass = true
				binary.Unmarshal(unixCmsg.Data[:linux.SizeOfControlMessageTClass], usermem.ByteOrder, &controlMessages.IP.TClass)

			case linux.IPV6_RECVORIGDSTADDR:
				var addr linux.SockAddrInet6
				binary.Unmarshal(unixCmsg.Data[:addr.SizeBytes()], usermem.ByteOrder, &addr)
				controlMessages.IP.OriginalDstAddress = &addr
			}

		case linux.SOL_TCP:
			switch unixCmsg.Header.Type {
			case linux.TCP_INQ:
				controlMessages.IP.HasInq = true
				binary.Unmarshal(unixCmsg.Data[:linux.SizeOfControlMessageInq], usermem.ByteOrder, &controlMessages.IP.Inq)
			}
		}
	}

	return int(n), msgFlags, senderAddr, uint32(len(senderAddrBuf)), controlMessages, nil
}

// SendMsg implements socket.Socket.SendMsg.
func (s *socketOpsCommon) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	// Only allow known and safe flags.
	if flags&^(syscall.MSG_DONTWAIT|syscall.MSG_EOR|syscall.MSG_FASTOPEN|syscall.MSG_MORE|syscall.MSG_NOSIGNAL) != 0 {
		return 0, syserr.ErrInvalidArgument
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
		sysflags := flags | syscall.MSG_DONTWAIT

		if srcs.NumBlocks() == 1 && len(controlBuf) == 0 {
			// Skip allocating []syscall.Iovec.
			src := srcs.Head()
			n, _, errno := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(s.fd), src.Addr(), uintptr(src.Len()), uintptr(sysflags), uintptr(firstBytePtr(to)), uintptr(len(to)))
			if errno != 0 {
				return 0, translateIOSyscallError(errno)
			}
			return uint64(n), nil
		}

		iovs := safemem.IovecsFromBlockSeq(srcs)
		msg := syscall.Msghdr{
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
	if flags&syscall.MSG_DONTWAIT == 0 {
		for err == syserror.ErrWouldBlock {
			// We only expect blocking to come from the actual syscall, in which
			// case it can't have returned any data.
			if n != 0 {
				panic(fmt.Sprintf("CopyInTo: got (%d, %v), wanted (0, %v)", n, err, err))
			}
			if ch != nil {
				if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
					if err == syserror.ETIMEDOUT {
						err = syserror.ErrWouldBlock
					}
					break
				}
			} else {
				var e waiter.Entry
				e, ch = waiter.NewChannelEntry(nil)
				s.EventRegister(&e, waiter.EventOut)
				defer s.EventUnregister(&e)
			}
			n, err = src.CopyInTo(t, sendmsgFromBlocks)
		}
	}

	return int(n), syserr.FromError(err)
}

func translateIOSyscallError(err error) error {
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return syserror.ErrWouldBlock
	}
	return err
}

// State implements socket.Socket.State.
func (s *socketOpsCommon) State() uint32 {
	info := linux.TCPInfo{}
	buf, err := getsockopt(s.fd, syscall.SOL_TCP, syscall.TCP_INFO, linux.SizeOfTCPInfo)
	if err != nil {
		if err != syscall.ENOPROTOOPT {
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

	binary.Unmarshal(buf, usermem.ByteOrder, &info)
	return uint32(info.State)
}

// Type implements socket.Socket.Type.
func (s *socketOpsCommon) Type() (family int, skType linux.SockType, protocol int) {
	return s.family, s.stype, s.protocol
}

type socketProvider struct {
	family int
}

// Socket implements socket.Provider.Socket.
func (p *socketProvider) Socket(t *kernel.Task, stypeflags linux.SockType, protocol int) (*fs.File, *syserr.Error) {
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
	case syscall.SOCK_STREAM:
		switch protocol {
		case 0, syscall.IPPROTO_TCP:
			// ok
		default:
			return nil, nil
		}
	case syscall.SOCK_DGRAM:
		switch protocol {
		case 0, syscall.IPPROTO_UDP:
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
	fd, err := syscall.Socket(p.family, int(stype)|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, syserr.FromError(err)
	}
	return newSocketFile(t, p.family, stype, protocol, fd, stypeflags&syscall.SOCK_NONBLOCK != 0)
}

// Pair implements socket.Provider.Pair.
func (p *socketProvider) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	// Not supported by AF_INET/AF_INET6.
	return nil, nil, nil
}

// LINT.ThenChange(./socket_vfs2.go)

func init() {
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		socket.RegisterProvider(family, &socketProvider{family})
		socket.RegisterProviderVFS2(family, &socketProviderVFS2{family})
	}
}
