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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	sizeofInt32 = 4

	// sizeofSockaddr is the size in bytes of the largest sockaddr type
	// supported by this package.
	sizeofSockaddr = syscall.SizeofSockaddrInet6 // sizeof(sockaddr_in6) > sizeof(sockaddr_in)
)

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
	socket.SendReceiveTimeout

	family   int            // Read-only.
	stype    linux.SockType // Read-only.
	protocol int            // Read-only.
	fd       int            // must be O_NONBLOCK
	queue    waiter.Queue
}

var _ = socket.Socket(&socketOperations{})

func newSocketFile(ctx context.Context, family int, stype linux.SockType, protocol int, fd int, nonblock bool) (*fs.File, *syserr.Error) {
	s := &socketOperations{
		family:   family,
		stype:    stype,
		protocol: protocol,
		fd:       fd,
	}
	if err := fdnotifier.AddFD(int32(fd), &s.queue); err != nil {
		return nil, syserr.FromError(err)
	}
	dirent := socket.NewDirent(ctx, socketDevice)
	defer dirent.DecRef()
	return fs.NewFile(ctx, dirent, fs.FileFlags{NonBlocking: nonblock, Read: true, Write: true, NonSeekable: true}, s), nil
}

// Release implements fs.FileOperations.Release.
func (s *socketOperations) Release() {
	fdnotifier.RemoveFD(int32(s.fd))
	syscall.Close(s.fd)
}

// Readiness implements waiter.Waitable.Readiness.
func (s *socketOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(int32(s.fd), mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *socketOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.queue.EventRegister(e, mask)
	fdnotifier.UpdateFD(int32(s.fd))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *socketOperations) EventUnregister(e *waiter.Entry) {
	s.queue.EventUnregister(e)
	fdnotifier.UpdateFD(int32(s.fd))
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
		return readv(s.fd, iovecsFromBlockSeq(dsts))
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
		return writev(s.fd, iovecsFromBlockSeq(srcs))
	}))
	return int64(n), err
}

// Connect implements socket.Socket.Connect.
func (s *socketOperations) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
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
func (s *socketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (kdefs.FD, interface{}, uint32, *syserr.Error) {
	var peerAddr []byte
	var peerAddrlen uint32
	var peerAddrPtr *byte
	var peerAddrlenPtr *uint32
	if peerRequested {
		peerAddr = make([]byte, sizeofSockaddr)
		peerAddrlen = uint32(len(peerAddr))
		peerAddrPtr = &peerAddr[0]
		peerAddrlenPtr = &peerAddrlen
	}

	// Conservatively ignore all flags specified by the application and add
	// SOCK_NONBLOCK since socketOperations requires it.
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
		peerAddr = peerAddr[:peerAddrlen]
	}
	if syscallErr != nil {
		return 0, peerAddr, peerAddrlen, syserr.FromError(syscallErr)
	}

	f, err := newSocketFile(t, s.family, s.stype, s.protocol, fd, flags&syscall.SOCK_NONBLOCK != 0)
	if err != nil {
		syscall.Close(fd)
		return 0, nil, 0, err
	}
	defer f.DecRef()

	fdFlags := kernel.FDFlags{
		CloseOnExec: flags&syscall.SOCK_CLOEXEC != 0,
	}
	kfd, kerr := t.FDMap().NewFDFrom(0, f, fdFlags, t.ThreadGroup().Limits())
	t.Kernel().RecordSocket(f)
	return kfd, peerAddr, peerAddrlen, syserr.FromError(kerr)
}

// Bind implements socket.Socket.Bind.
func (s *socketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
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
func (s *socketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return syserr.FromError(syscall.Listen(s.fd, backlog))
}

// Shutdown implements socket.Socket.Shutdown.
func (s *socketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	switch how {
	case syscall.SHUT_RD, syscall.SHUT_WR, syscall.SHUT_RDWR:
		return syserr.FromError(syscall.Shutdown(s.fd, how))
	default:
		return syserr.ErrInvalidArgument
	}
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *socketOperations) GetSockOpt(t *kernel.Task, level int, name int, outLen int) (interface{}, *syserr.Error) {
	if outLen < 0 {
		return nil, syserr.ErrInvalidArgument
	}

	// Whitelist options and constrain option length.
	var optlen int
	switch level {
	case syscall.SOL_IPV6:
		switch name {
		case syscall.IPV6_V6ONLY:
			optlen = sizeofInt32
		}
	case syscall.SOL_SOCKET:
		switch name {
		case syscall.SO_ERROR, syscall.SO_KEEPALIVE, syscall.SO_SNDBUF, syscall.SO_RCVBUF, syscall.SO_REUSEADDR:
			optlen = sizeofInt32
		case syscall.SO_LINGER:
			optlen = syscall.SizeofLinger
		}
	case syscall.SOL_TCP:
		switch name {
		case syscall.TCP_NODELAY:
			optlen = sizeofInt32
		case syscall.TCP_INFO:
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
	return opt, nil
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *socketOperations) SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error {
	// Whitelist options and constrain option length.
	var optlen int
	switch level {
	case syscall.SOL_IPV6:
		switch name {
		case syscall.IPV6_V6ONLY:
			optlen = sizeofInt32
		}
	case syscall.SOL_SOCKET:
		switch name {
		case syscall.SO_SNDBUF, syscall.SO_RCVBUF, syscall.SO_REUSEADDR:
			optlen = sizeofInt32
		}
	case syscall.SOL_TCP:
		switch name {
		case syscall.TCP_NODELAY:
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
func (s *socketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (int, int, interface{}, uint32, socket.ControlMessages, *syserr.Error) {
	// Whitelist flags.
	//
	// FIXME(jamieliu): We can't support MSG_ERRQUEUE because it uses ancillary
	// messages that netstack/tcpip/transport/unix doesn't understand. Kill the
	// Socket interface's dependence on netstack.
	if flags&^(syscall.MSG_DONTWAIT|syscall.MSG_PEEK|syscall.MSG_TRUNC) != 0 {
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrInvalidArgument
	}

	var senderAddr []byte
	if senderRequested {
		senderAddr = make([]byte, sizeofSockaddr)
	}

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

		if dsts.NumBlocks() == 1 {
			// Skip allocating []syscall.Iovec.
			return recvfrom(s.fd, dsts.Head().ToSlice(), sysflags, &senderAddr)
		}

		iovs := iovecsFromBlockSeq(dsts)
		msg := syscall.Msghdr{
			Iov:    &iovs[0],
			Iovlen: uint64(len(iovs)),
		}
		if len(senderAddr) != 0 {
			msg.Name = &senderAddr[0]
			msg.Namelen = uint32(len(senderAddr))
		}
		n, err := recvmsg(s.fd, &msg, sysflags)
		if err != nil {
			return 0, err
		}
		senderAddr = senderAddr[:msg.Namelen]
		msgFlags = int(msg.Flags)
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

	// We don't allow control messages.
	msgFlags &^= linux.MSG_CTRUNC

	return int(n), msgFlags, senderAddr, uint32(len(senderAddr)), socket.ControlMessages{}, syserr.FromError(err)
}

// SendMsg implements socket.Socket.SendMsg.
func (s *socketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	// Whitelist flags.
	if flags&^(syscall.MSG_DONTWAIT|syscall.MSG_EOR|syscall.MSG_FASTOPEN|syscall.MSG_MORE|syscall.MSG_NOSIGNAL) != 0 {
		return 0, syserr.ErrInvalidArgument
	}

	sendmsgFromBlocks := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		// Refuse to do anything if any part of src.Addrs was unusable.
		if uint64(src.NumBytes()) != srcs.NumBytes() {
			return 0, nil
		}
		if srcs.IsEmpty() {
			return 0, nil
		}

		// We always do a non-blocking send*().
		sysflags := flags | syscall.MSG_DONTWAIT

		if srcs.NumBlocks() == 1 {
			// Skip allocating []syscall.Iovec.
			src := srcs.Head()
			n, _, errno := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(s.fd), src.Addr(), uintptr(src.Len()), uintptr(sysflags), uintptr(firstBytePtr(to)), uintptr(len(to)))
			if errno != 0 {
				return 0, translateIOSyscallError(errno)
			}
			return uint64(n), nil
		}

		iovs := iovecsFromBlockSeq(srcs)
		msg := syscall.Msghdr{
			Iov:    &iovs[0],
			Iovlen: uint64(len(iovs)),
		}
		if len(to) != 0 {
			msg.Name = &to[0]
			msg.Namelen = uint32(len(to))
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

func iovecsFromBlockSeq(bs safemem.BlockSeq) []syscall.Iovec {
	iovs := make([]syscall.Iovec, 0, bs.NumBlocks())
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		b := bs.Head()
		iovs = append(iovs, syscall.Iovec{
			Base: &b.ToSlice()[0],
			Len:  uint64(b.Len()),
		})
		// We don't need to care about b.NeedSafecopy(), because the host
		// kernel will handle such address ranges just fine (by returning
		// EFAULT).
	}
	return iovs
}

func translateIOSyscallError(err error) error {
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return syserror.ErrWouldBlock
	}
	return err
}

// State implements socket.Socket.State.
func (s *socketOperations) State() uint32 {
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
func (s *socketOperations) Type() (family int, skType linux.SockType, protocol int) {
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

func init() {
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		socket.RegisterProvider(family, &socketProvider{family})
	}
}
