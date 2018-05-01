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

package linux

import (
	"syscall"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
)

// minListenBacklog is the minimum reasonable backlog for listening sockets.
const minListenBacklog = 8

// maxListenBacklog is the maximum allowed backlog for listening sockets.
const maxListenBacklog = 1024

// maxAddrLen is the maximum socket address length we're willing to accept.
const maxAddrLen = 200

// maxOptLen is the maximum sockopt parameter length we're willing to accept.
const maxOptLen = 1024

// maxControlLen is the maximum length of the msghdr.msg_control buffer we're
// willing to accept. Note that this limit is smaller than Linux, which allows
// buffers upto INT_MAX.
const maxControlLen = 10 * 1024 * 1024

// nameLenOffset is the offset from the start of the MessageHeader64 struct to
// the NameLen field.
const nameLenOffset = 8

// controlLenOffset is the offset form the start of the MessageHeader64 struct
// to the ControlLen field.
const controlLenOffset = 40

// messageHeader64Len is the length of a MessageHeader64 struct.
var messageHeader64Len = uint64(binary.Size(MessageHeader64{}))

// multipleMessageHeader64Len is the length of a multipeMessageHeader64 struct.
var multipleMessageHeader64Len = uint64(binary.Size(multipleMessageHeader64{}))

// MessageHeader64 is the 64-bit representation of the msghdr struct used in
// the recvmsg and sendmsg syscalls.
type MessageHeader64 struct {
	// Name is the optional pointer to a network address buffer.
	Name uint64

	// NameLen is the length of the buffer pointed to by Name.
	NameLen uint32
	_       uint32

	// Iov is a pointer to an array of io vectors that describe the memory
	// locations involved in the io operation.
	Iov uint64

	// IovLen is the length of the array pointed to by Iov.
	IovLen uint64

	// Control is the optional pointer to ancillary control data.
	Control uint64

	// ControlLen is the length of the data pointed to by Control.
	ControlLen uint64

	// Flags on the sent/received message.
	Flags int32
	_     int32
}

// multipleMessageHeader64 is the 64-bit representation of the mmsghdr struct used in
// the recvmmsg and sendmmsg syscalls.
type multipleMessageHeader64 struct {
	msgHdr MessageHeader64
	msgLen uint32
	_      int32
}

// CopyInMessageHeader64 copies a message header from user to kernel memory.
func CopyInMessageHeader64(t *kernel.Task, addr usermem.Addr, msg *MessageHeader64) error {
	b := t.CopyScratchBuffer(52)
	if _, err := t.CopyInBytes(addr, b); err != nil {
		return err
	}

	msg.Name = usermem.ByteOrder.Uint64(b[0:])
	msg.NameLen = usermem.ByteOrder.Uint32(b[8:])
	msg.Iov = usermem.ByteOrder.Uint64(b[16:])
	msg.IovLen = usermem.ByteOrder.Uint64(b[24:])
	msg.Control = usermem.ByteOrder.Uint64(b[32:])
	msg.ControlLen = usermem.ByteOrder.Uint64(b[40:])
	msg.Flags = int32(usermem.ByteOrder.Uint32(b[48:]))

	return nil
}

// CaptureAddress allocates memory for and copies a socket address structure
// from the untrusted address space range.
func CaptureAddress(t *kernel.Task, addr usermem.Addr, addrlen uint32) ([]byte, error) {
	if addrlen > maxAddrLen {
		return nil, syscall.EINVAL
	}

	addrBuf := make([]byte, addrlen)
	if _, err := t.CopyInBytes(addr, addrBuf); err != nil {
		return nil, err
	}

	return addrBuf, nil
}

// writeAddress writes a sockaddr structure and its length to an output buffer
// in the unstrusted address space range. If the address is bigger than the
// buffer, it is truncated.
func writeAddress(t *kernel.Task, addr interface{}, addrLen uint32, addrPtr usermem.Addr, addrLenPtr usermem.Addr) error {
	// Get the buffer length.
	var bufLen uint32
	if _, err := t.CopyIn(addrLenPtr, &bufLen); err != nil {
		return err
	}

	if int32(bufLen) < 0 {
		return syscall.EINVAL
	}

	// Write the length unconditionally.
	if _, err := t.CopyOut(addrLenPtr, addrLen); err != nil {
		return err
	}

	if addr == nil {
		return nil
	}

	if bufLen > addrLen {
		bufLen = addrLen
	}

	// Copy as much of the address as will fit in the buffer.
	encodedAddr := binary.Marshal(nil, usermem.ByteOrder, addr)
	if bufLen > uint32(len(encodedAddr)) {
		bufLen = uint32(len(encodedAddr))
	}
	_, err := t.CopyOutBytes(addrPtr, encodedAddr[:int(bufLen)])
	return err
}

// Socket implements the linux syscall socket(2).
func Socket(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	domain := int(args[0].Int())
	stype := args[1].Int()
	protocol := int(args[2].Int())

	// Check and initialize the flags.
	if stype & ^(0xf|linux.SOCK_NONBLOCK|linux.SOCK_CLOEXEC) != 0 {
		return 0, nil, syscall.EINVAL
	}

	// Create the new socket.
	s, e := socket.New(t, domain, unix.SockType(stype&0xf), protocol)
	if e != nil {
		return 0, nil, e.ToError()
	}
	s.SetFlags(fs.SettableFileFlags{
		NonBlocking: stype&linux.SOCK_NONBLOCK != 0,
	})
	defer s.DecRef()

	fd, err := t.FDMap().NewFDFrom(0, s, kernel.FDFlags{
		CloseOnExec: stype&linux.SOCK_CLOEXEC != 0,
	}, t.ThreadGroup().Limits())
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// SocketPair implements the linux syscall socketpair(2).
func SocketPair(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	domain := int(args[0].Int())
	stype := args[1].Int()
	protocol := int(args[2].Int())
	socks := args[3].Pointer()

	// Check and initialize the flags.
	if stype & ^(0xf|linux.SOCK_NONBLOCK|linux.SOCK_CLOEXEC) != 0 {
		return 0, nil, syscall.EINVAL
	}

	fileFlags := fs.SettableFileFlags{
		NonBlocking: stype&linux.SOCK_NONBLOCK != 0,
	}
	fdFlags := kernel.FDFlags{
		CloseOnExec: stype&linux.SOCK_CLOEXEC != 0,
	}

	// Create the socket pair.
	s1, s2, e := socket.Pair(t, domain, unix.SockType(stype&0xf), protocol)
	if e != nil {
		return 0, nil, e.ToError()
	}
	s1.SetFlags(fileFlags)
	s2.SetFlags(fileFlags)
	defer s1.DecRef()
	defer s2.DecRef()

	// Create the FDs for the sockets.
	fd1, err := t.FDMap().NewFDFrom(0, s1, fdFlags, t.ThreadGroup().Limits())
	if err != nil {
		return 0, nil, err
	}
	fd2, err := t.FDMap().NewFDFrom(0, s2, fdFlags, t.ThreadGroup().Limits())
	if err != nil {
		t.FDMap().Remove(fd1)
		return 0, nil, err
	}

	// Copy the file descriptors out.
	if _, err := t.CopyOut(socks, []int32{int32(fd1), int32(fd2)}); err != nil {
		t.FDMap().Remove(fd1)
		t.FDMap().Remove(fd2)
		return 0, nil, err
	}

	return 0, nil, nil
}

// Connect implements the linux syscall connect(2).
func Connect(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	addrlen := args[2].Uint()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Capture address and call syscall implementation.
	a, err := CaptureAddress(t, addr, addrlen)
	if err != nil {
		return 0, nil, err
	}

	blocking := !file.Flags().NonBlocking
	return 0, nil, syserror.ConvertIntr(s.Connect(t, a, blocking).ToError(), kernel.ERESTARTSYS)
}

// accept is the implementation of the accept syscall. It is called by accept
// and accept4 syscall handlers.
func accept(t *kernel.Task, fd kdefs.FD, addr usermem.Addr, addrLen usermem.Addr, flags int) (uintptr, error) {
	// Check that no unsupported flags are passed in.
	if flags & ^(linux.SOCK_NONBLOCK|linux.SOCK_CLOEXEC) != 0 {
		return 0, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, syscall.ENOTSOCK
	}

	// Call the syscall implementation for this socket, then copy the
	// output address if one is specified.
	blocking := !file.Flags().NonBlocking

	peerRequested := addrLen != 0
	nfd, peer, peerLen, e := s.Accept(t, peerRequested, flags, blocking)
	if e != nil {
		return 0, syserror.ConvertIntr(e.ToError(), kernel.ERESTARTSYS)
	}
	if peerRequested {
		// NOTE: Linux does not give you an error if it can't
		// write the data back out so neither do we.
		if err := writeAddress(t, peer, peerLen, addr, addrLen); err == syscall.EINVAL {
			return 0, err
		}
	}
	return uintptr(nfd), nil
}

// Accept4 implements the linux syscall accept4(2).
func Accept4(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	addrlen := args[2].Pointer()
	flags := int(args[3].Int())

	n, err := accept(t, fd, addr, addrlen, flags)
	return n, nil, err
}

// Accept implements the linux syscall accept(2).
func Accept(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	addrlen := args[2].Pointer()

	n, err := accept(t, fd, addr, addrlen, 0)
	return n, nil, err
}

// Bind implements the linux syscall bind(2).
func Bind(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	addrlen := args[2].Uint()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Capture address and call syscall implementation.
	a, err := CaptureAddress(t, addr, addrlen)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, s.Bind(t, a).ToError()
}

// Listen implements the linux syscall listen(2).
func Listen(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	backlog := args[1].Int()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Per Linux, the backlog is silently capped to reasonable values.
	if backlog <= 0 {
		backlog = minListenBacklog
	}
	if backlog > maxListenBacklog {
		backlog = maxListenBacklog
	}

	return 0, nil, s.Listen(t, int(backlog)).ToError()
}

// Shutdown implements the linux syscall shutdown(2).
func Shutdown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	how := args[1].Int()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Validate how, then call syscall implementation.
	switch how {
	case linux.SHUT_RD, linux.SHUT_WR, linux.SHUT_RDWR:
	default:
		return 0, nil, syscall.EINVAL
	}

	return 0, nil, s.Shutdown(t, int(how)).ToError()
}

// GetSockOpt implements the linux syscall getsockopt(2).
func GetSockOpt(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	level := args[1].Int()
	name := args[2].Int()
	optValAddr := args[3].Pointer()
	optLenAddr := args[4].Pointer()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Read the length if present. Reject negative values.
	optLen := int32(0)
	if optLenAddr != 0 {
		if _, err := t.CopyIn(optLenAddr, &optLen); err != nil {
			return 0, nil, err
		}

		if optLen < 0 {
			return 0, nil, syscall.EINVAL
		}
	}

	// Call syscall implementation then copy both value and value len out.
	v, e := s.GetSockOpt(t, int(level), int(name), int(optLen))
	if e != nil {
		return 0, nil, e.ToError()
	}

	if optLenAddr != 0 {
		vLen := int32(binary.Size(v))
		if _, err := t.CopyOut(optLenAddr, vLen); err != nil {
			return 0, nil, err
		}
	}

	if v != nil {
		if _, err := t.CopyOut(optValAddr, v); err != nil {
			return 0, nil, err
		}
	}

	return 0, nil, nil
}

// SetSockOpt implements the linux syscall setsockopt(2).
//
// Note that unlike Linux, enabling SO_PASSCRED does not autobind the socket.
func SetSockOpt(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	level := args[1].Int()
	name := args[2].Int()
	optValAddr := args[3].Pointer()
	optLen := args[4].Int()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	if optLen <= 0 {
		return 0, nil, syscall.EINVAL
	}
	if optLen > maxOptLen {
		return 0, nil, syscall.EINVAL
	}
	buf := make([]byte, optLen)
	if _, err := t.CopyIn(optValAddr, &buf); err != nil {
		return 0, nil, err
	}

	// Call syscall implementation.
	if err := s.SetSockOpt(t, int(level), int(name), buf); err != nil {
		return 0, nil, err.ToError()
	}

	return 0, nil, nil
}

// GetSockName implements the linux syscall getsockname(2).
func GetSockName(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	addrlen := args[2].Pointer()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Get the socket name and copy it to the caller.
	v, vl, err := s.GetSockName(t)
	if err != nil {
		return 0, nil, err.ToError()
	}

	return 0, nil, writeAddress(t, v, vl, addr, addrlen)
}

// GetPeerName implements the linux syscall getpeername(2).
func GetPeerName(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	addrlen := args[2].Pointer()

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Get the socket peer name and copy it to the caller.
	v, vl, err := s.GetPeerName(t)
	if err != nil {
		return 0, nil, err.ToError()
	}

	return 0, nil, writeAddress(t, v, vl, addr, addrlen)
}

// RecvMsg implements the linux syscall recvmsg(2).
func RecvMsg(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	msgPtr := args[1].Pointer()
	flags := args[2].Int()

	if t.Arch().Width() != 8 {
		// We only handle 64-bit for now.
		return 0, nil, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Reject flags that we don't handle yet.
	if flags & ^(linux.MSG_DONTWAIT|linux.MSG_NOSIGNAL|linux.MSG_PEEK|linux.MSG_TRUNC|linux.MSG_CMSG_CLOEXEC|linux.MSG_ERRQUEUE) != 0 {
		return 0, nil, syscall.EINVAL
	}

	if file.Flags().NonBlocking {
		flags |= linux.MSG_DONTWAIT
	}

	var haveDeadline bool
	var deadline ktime.Time
	if dl := s.RecvTimeout(); dl != 0 {
		deadline = t.Kernel().MonotonicClock().Now().Add(time.Duration(dl) * time.Nanosecond)
		haveDeadline = true
	}

	n, err := recvSingleMsg(t, s, msgPtr, flags, haveDeadline, deadline)
	return n, nil, err
}

// RecvMMsg implements the linux syscall recvmmsg(2).
func RecvMMsg(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	msgPtr := args[1].Pointer()
	vlen := args[2].Uint()
	flags := args[3].Int()
	toPtr := args[4].Pointer()

	if t.Arch().Width() != 8 {
		// We only handle 64-bit for now.
		return 0, nil, syscall.EINVAL
	}

	// Reject flags that we don't handle yet.
	if flags & ^(linux.MSG_DONTWAIT|linux.MSG_NOSIGNAL|linux.MSG_TRUNC|linux.MSG_CMSG_CLOEXEC|linux.MSG_ERRQUEUE) != 0 {
		return 0, nil, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	if file.Flags().NonBlocking {
		flags |= linux.MSG_DONTWAIT
	}

	var haveDeadline bool
	var deadline ktime.Time
	if toPtr != 0 {
		ts, err := copyTimespecIn(t, toPtr)
		if err != nil {
			return 0, nil, err
		}
		if !ts.Valid() {
			return 0, nil, syscall.EINVAL
		}
		deadline = t.Kernel().MonotonicClock().Now().Add(ts.ToDuration())
		haveDeadline = true
	}

	if !haveDeadline {
		dl := s.RecvTimeout()
		if dl != 0 {
			deadline = t.Kernel().MonotonicClock().Now().Add(time.Duration(dl) * time.Nanosecond)
			haveDeadline = true
		}
	}

	var count uint32
	var err error
	for i := uint64(0); i < uint64(vlen); i++ {
		mp, ok := msgPtr.AddLength(i * multipleMessageHeader64Len)
		if !ok {
			return 0, nil, syscall.EFAULT
		}
		var n uintptr
		if n, err = recvSingleMsg(t, s, mp, flags, haveDeadline, deadline); err != nil {
			break
		}

		// Copy the received length to the caller.
		lp, ok := mp.AddLength(messageHeader64Len)
		if !ok {
			return 0, nil, syscall.EFAULT
		}
		if _, err = t.CopyOut(lp, uint32(n)); err != nil {
			break
		}
		count++
	}

	if count == 0 {
		return 0, nil, err
	}
	return uintptr(count), nil, nil
}

func recvSingleMsg(t *kernel.Task, s socket.Socket, msgPtr usermem.Addr, flags int32, haveDeadline bool, deadline ktime.Time) (uintptr, error) {
	// Capture the message header and io vectors.
	var msg MessageHeader64
	if err := CopyInMessageHeader64(t, msgPtr, &msg); err != nil {
		return 0, err
	}

	if msg.IovLen > linux.UIO_MAXIOV {
		return 0, syscall.EMSGSIZE
	}
	dst, err := t.IovecsIOSequence(usermem.Addr(msg.Iov), int(msg.IovLen), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, err
	}

	// FIXME: Pretend we have an empty error queue.
	if flags&linux.MSG_ERRQUEUE != 0 {
		return 0, syscall.EAGAIN
	}

	// Fast path when no control message nor name buffers are provided.
	if msg.ControlLen == 0 && msg.NameLen == 0 {
		n, _, _, _, err := s.RecvMsg(t, dst, int(flags), haveDeadline, deadline, false, 0)
		if err != nil {
			return 0, syserror.ConvertIntr(err.ToError(), kernel.ERESTARTSYS)
		}
		return uintptr(n), nil
	}

	if msg.ControlLen > maxControlLen {
		return 0, syscall.ENOBUFS
	}
	n, sender, senderLen, cms, e := s.RecvMsg(t, dst, int(flags), haveDeadline, deadline, msg.NameLen != 0, msg.ControlLen)
	if e != nil {
		return 0, syserror.ConvertIntr(e.ToError(), kernel.ERESTARTSYS)
	}
	defer cms.Release()

	controlData := make([]byte, 0, msg.ControlLen)

	if cr, ok := s.(unix.Credentialer); ok && cr.Passcred() {
		creds, _ := cms.Credentials.(control.SCMCredentials)
		controlData = control.PackCredentials(t, creds, controlData)
	}

	if cms.Rights != nil {
		controlData = control.PackRights(t, cms.Rights.(control.SCMRights), flags&linux.MSG_CMSG_CLOEXEC != 0, controlData)
	}

	// Copy the address to the caller.
	if msg.NameLen != 0 {
		if err := writeAddress(t, sender, senderLen, usermem.Addr(msg.Name), usermem.Addr(msgPtr+nameLenOffset)); err != nil {
			return 0, err
		}
	}

	// Copy the control data to the caller.
	if _, err := t.CopyOut(msgPtr+controlLenOffset, uint64(len(controlData))); err != nil {
		return 0, err
	}
	if len(controlData) > 0 {
		if _, err := t.CopyOut(usermem.Addr(msg.Control), controlData); err != nil {
			return 0, err
		}
	}

	return uintptr(n), nil
}

// recvFrom is the implementation of the recvfrom syscall. It is called by
// recvfrom and recv syscall handlers.
func recvFrom(t *kernel.Task, fd kdefs.FD, bufPtr usermem.Addr, bufLen uint64, flags int32, namePtr usermem.Addr, nameLenPtr usermem.Addr) (uintptr, error) {
	if int(bufLen) < 0 {
		return 0, syscall.EINVAL
	}

	// Reject flags that we don't handle yet.
	if flags & ^(linux.MSG_DONTWAIT|linux.MSG_NOSIGNAL|linux.MSG_PEEK|linux.MSG_TRUNC) != 0 {
		return 0, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, syscall.ENOTSOCK
	}

	if file.Flags().NonBlocking {
		flags |= linux.MSG_DONTWAIT
	}

	dst, err := t.SingleIOSequence(bufPtr, int(bufLen), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, err
	}

	var haveDeadline bool
	var deadline ktime.Time

	if dl := s.RecvTimeout(); dl != 0 {
		deadline = t.Kernel().MonotonicClock().Now().Add(time.Duration(dl) * time.Nanosecond)
		haveDeadline = true
	}

	n, sender, senderLen, cm, e := s.RecvMsg(t, dst, int(flags), haveDeadline, deadline, nameLenPtr != 0, 0)
	cm.Release()
	if e != nil {
		return 0, syserror.ConvertIntr(e.ToError(), kernel.ERESTARTSYS)
	}

	// Copy the address to the caller.
	if nameLenPtr != 0 {
		if err := writeAddress(t, sender, senderLen, namePtr, nameLenPtr); err != nil {
			return 0, err
		}
	}

	return uintptr(n), nil
}

// RecvFrom implements the linux syscall recvfrom(2).
func RecvFrom(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	bufPtr := args[1].Pointer()
	bufLen := args[2].Uint64()
	flags := args[3].Int()
	namePtr := args[4].Pointer()
	nameLenPtr := args[5].Pointer()

	n, err := recvFrom(t, fd, bufPtr, bufLen, flags, namePtr, nameLenPtr)
	return n, nil, err
}

// SendMsg implements the linux syscall sendmsg(2).
func SendMsg(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	msgPtr := args[1].Pointer()
	flags := args[2].Int()

	if t.Arch().Width() != 8 {
		// We only handle 64-bit for now.
		return 0, nil, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Reject flags that we don't handle yet.
	if flags & ^(linux.MSG_DONTWAIT|linux.MSG_EOR|linux.MSG_MORE|linux.MSG_NOSIGNAL) != 0 {
		return 0, nil, syscall.EINVAL
	}

	if file.Flags().NonBlocking {
		flags |= linux.MSG_DONTWAIT
	}

	n, err := sendSingleMsg(t, s, file, msgPtr, flags)
	return n, nil, err
}

// SendMMsg implements the linux syscall sendmmsg(2).
func SendMMsg(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	msgPtr := args[1].Pointer()
	vlen := args[2].Uint()
	flags := args[3].Int()

	if t.Arch().Width() != 8 {
		// We only handle 64-bit for now.
		return 0, nil, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, nil, syscall.ENOTSOCK
	}

	// Reject flags that we don't handle yet.
	if flags & ^(linux.MSG_DONTWAIT|linux.MSG_EOR|linux.MSG_MORE|linux.MSG_NOSIGNAL) != 0 {
		return 0, nil, syscall.EINVAL
	}

	if file.Flags().NonBlocking {
		flags |= linux.MSG_DONTWAIT
	}

	var count uint32
	var err error
	for i := uint64(0); i < uint64(vlen); i++ {
		mp, ok := msgPtr.AddLength(i * multipleMessageHeader64Len)
		if !ok {
			return 0, nil, syscall.EFAULT
		}
		var n uintptr
		if n, err = sendSingleMsg(t, s, file, mp, flags); err != nil {
			break
		}

		// Copy the received length to the caller.
		lp, ok := mp.AddLength(messageHeader64Len)
		if !ok {
			return 0, nil, syscall.EFAULT
		}
		if _, err = t.CopyOut(lp, uint32(n)); err != nil {
			break
		}
		count++
	}

	if count == 0 {
		return 0, nil, err
	}
	return uintptr(count), nil, nil
}

func sendSingleMsg(t *kernel.Task, s socket.Socket, file *fs.File, msgPtr usermem.Addr, flags int32) (uintptr, error) {
	// Capture the message header.
	var msg MessageHeader64
	if err := CopyInMessageHeader64(t, msgPtr, &msg); err != nil {
		return 0, err
	}

	var controlData []byte
	if msg.ControlLen > 0 {
		// Put an upper bound to prevent large allocations.
		if msg.ControlLen > maxControlLen {
			return 0, syscall.ENOBUFS
		}
		controlData = make([]byte, msg.ControlLen)
		if _, err := t.CopyIn(usermem.Addr(msg.Control), &controlData); err != nil {
			return 0, err
		}
	}

	// Read the destination address if one is specified.
	var to []byte
	if msg.NameLen != 0 {
		var err error
		to, err = CaptureAddress(t, usermem.Addr(msg.Name), msg.NameLen)
		if err != nil {
			return 0, err
		}
	}

	// Read data then call the sendmsg implementation.
	if msg.IovLen > linux.UIO_MAXIOV {
		return 0, syscall.EMSGSIZE
	}
	src, err := t.IovecsIOSequence(usermem.Addr(msg.Iov), int(msg.IovLen), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, err
	}

	controlMessages, err := control.Parse(t, s, controlData)
	if err != nil {
		return 0, err
	}

	// Call the syscall implementation.
	n, e := s.SendMsg(t, src, to, int(flags), controlMessages)
	err = handleIOError(t, n != 0, e.ToError(), kernel.ERESTARTSYS, "sendmsg", file)
	if err != nil {
		controlMessages.Release()
	}
	return uintptr(n), err
}

// sendTo is the implementation of the sendto syscall. It is called by sendto
// and send syscall handlers.
func sendTo(t *kernel.Task, fd kdefs.FD, bufPtr usermem.Addr, bufLen uint64, flags int32, namePtr usermem.Addr, nameLen uint32) (uintptr, error) {
	bl := int(bufLen)
	if bl < 0 {
		return 0, syscall.EINVAL
	}

	// Get socket from the file descriptor.
	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, syscall.EBADF
	}
	defer file.DecRef()

	// Extract the socket.
	s, ok := file.FileOperations.(socket.Socket)
	if !ok {
		return 0, syscall.ENOTSOCK
	}

	if file.Flags().NonBlocking {
		flags |= linux.MSG_DONTWAIT
	}

	// Read the destination address if one is specified.
	var to []byte
	var err error
	if namePtr != 0 {
		to, err = CaptureAddress(t, namePtr, nameLen)
		if err != nil {
			return 0, err
		}
	}

	src, err := t.SingleIOSequence(bufPtr, bl, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, err
	}

	// Call the syscall implementation.
	n, e := s.SendMsg(t, src, to, int(flags), control.New(t, s, nil))
	return uintptr(n), handleIOError(t, n != 0, e.ToError(), kernel.ERESTARTSYS, "sendto", file)
}

// SendTo implements the linux syscall sendto(2).
func SendTo(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	bufPtr := args[1].Pointer()
	bufLen := args[2].Uint64()
	flags := args[3].Int()
	namePtr := args[4].Pointer()
	nameLen := args[5].Uint()

	n, err := sendTo(t, fd, bufPtr, bufLen, flags, namePtr, nameLen)
	return n, nil, err
}
