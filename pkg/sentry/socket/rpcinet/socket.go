// Copyright 2018 Google LLC
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

package rpcinet

import (
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/conn"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/notifier"
	pb "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/syscall_rpc_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/sentry/unimpl"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// socketOperations implements fs.FileOperations and socket.Socket for a socket
// implemented using a host socket.
type socketOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	socket.SendReceiveTimeout

	family   int    // Read-only.
	fd       uint32 // must be O_NONBLOCK
	wq       *waiter.Queue
	rpcConn  *conn.RPCConnection
	notifier *notifier.Notifier

	// shState is the state of the connection with respect to shutdown. Because
	// we're mixing non-blocking semantics on the other side we have to adapt for
	// some strange differences between blocking and non-blocking sockets.
	shState int32
}

// Verify that we actually implement socket.Socket.
var _ = socket.Socket(&socketOperations{})

// New creates a new RPC socket.
func newSocketFile(ctx context.Context, stack *Stack, family int, skType int, protocol int) (*fs.File, *syserr.Error) {
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Socket{&pb.SocketRequest{Family: int64(family), Type: int64(skType | syscall.SOCK_NONBLOCK), Protocol: int64(protocol)}}}, false /* ignoreResult */)
	<-c

	res := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Socket).Socket.Result
	if e, ok := res.(*pb.SocketResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}
	fd := res.(*pb.SocketResponse_Fd).Fd

	var wq waiter.Queue
	stack.notifier.AddFD(fd, &wq)

	dirent := socket.NewDirent(ctx, socketDevice)
	defer dirent.DecRef()
	return fs.NewFile(ctx, dirent, fs.FileFlags{Read: true, Write: true}, &socketOperations{
		family:   family,
		wq:       &wq,
		fd:       fd,
		rpcConn:  stack.rpcConn,
		notifier: stack.notifier,
	}), nil
}

func isBlockingErrno(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}

func translateIOSyscallError(err error) error {
	if isBlockingErrno(err) {
		return syserror.ErrWouldBlock
	}
	return err
}

// setShutdownFlags will set the shutdown flag so we can handle blocking reads
// after a read shutdown.
func (s *socketOperations) setShutdownFlags(how int) {
	var f tcpip.ShutdownFlags
	switch how {
	case linux.SHUT_RD:
		f = tcpip.ShutdownRead
	case linux.SHUT_WR:
		f = tcpip.ShutdownWrite
	case linux.SHUT_RDWR:
		f = tcpip.ShutdownWrite | tcpip.ShutdownRead
	}

	// Atomically update the flags.
	for {
		old := atomic.LoadInt32(&s.shState)
		if atomic.CompareAndSwapInt32(&s.shState, old, old|int32(f)) {
			break
		}
	}
}

func (s *socketOperations) resetShutdownFlags() {
	atomic.StoreInt32(&s.shState, 0)
}

func (s *socketOperations) isShutRdSet() bool {
	return atomic.LoadInt32(&s.shState)&int32(tcpip.ShutdownRead) != 0
}

func (s *socketOperations) isShutWrSet() bool {
	return atomic.LoadInt32(&s.shState)&int32(tcpip.ShutdownWrite) != 0
}

// Release implements fs.FileOperations.Release.
func (s *socketOperations) Release() {
	s.notifier.RemoveFD(s.fd)

	// We always need to close the FD.
	_, _ = s.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Close{&pb.CloseRequest{Fd: s.fd}}}, true /* ignoreResult */)
}

// Readiness implements waiter.Waitable.Readiness.
func (s *socketOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.notifier.NonBlockingPoll(s.fd, mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *socketOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.wq.EventRegister(e, mask)
	s.notifier.UpdateFD(s.fd)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *socketOperations) EventUnregister(e *waiter.Entry) {
	s.wq.EventUnregister(e)
	s.notifier.UpdateFD(s.fd)
}

func rpcRead(t *kernel.Task, req *pb.SyscallRequest_Read) (*pb.ReadResponse_Data, *syserr.Error) {
	s := t.NetworkContext().(*Stack)
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Read).Read.Result
	if e, ok := res.(*pb.ReadResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.ReadResponse_Data), nil
}

// Read implements fs.FileOperations.Read.
func (s *socketOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	req := &pb.SyscallRequest_Read{&pb.ReadRequest{
		Fd:     s.fd,
		Length: uint32(dst.NumBytes()),
	}}

	res, se := rpcRead(ctx.(*kernel.Task), req)
	if se == nil {
		n, e := dst.CopyOut(ctx, res.Data)
		return int64(n), e
	}

	return 0, se.ToError()
}

func rpcWrite(t *kernel.Task, req *pb.SyscallRequest_Write) (uint32, *syserr.Error) {
	s := t.NetworkContext().(*Stack)
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Write).Write.Result
	if e, ok := res.(*pb.WriteResponse_ErrorNumber); ok {
		return 0, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.WriteResponse_Length).Length, nil
}

// Write implements fs.FileOperations.Write.
func (s *socketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	t := ctx.(*kernel.Task)
	v := buffer.NewView(int(src.NumBytes()))

	// Copy all the data into the buffer.
	if _, err := src.CopyIn(t, v); err != nil {
		return 0, err
	}

	n, err := rpcWrite(t, &pb.SyscallRequest_Write{&pb.WriteRequest{Fd: s.fd, Data: v}})
	if n > 0 && n < uint32(src.NumBytes()) {
		// The FileOperations.Write interface expects us to return ErrWouldBlock in
		// the event of a partial write.
		return int64(n), syserror.ErrWouldBlock
	}
	return int64(n), err.ToError()
}

func rpcConnect(t *kernel.Task, fd uint32, sockaddr []byte) *syserr.Error {
	s := t.NetworkContext().(*Stack)
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Connect{&pb.ConnectRequest{Fd: uint32(fd), Address: sockaddr}}}, false /* ignoreResult */)
	<-c

	if e := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Connect).Connect.ErrorNumber; e != 0 {
		return syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

// Connect implements socket.Socket.Connect.
func (s *socketOperations) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	if !blocking {
		e := rpcConnect(t, s.fd, sockaddr)
		if e == nil {
			// Reset the shutdown state on new connects.
			s.resetShutdownFlags()
		}
		return e
	}

	// Register for notification when the endpoint becomes writable, then
	// initiate the connection.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut|waiter.EventIn|waiter.EventHUp)
	defer s.EventUnregister(&e)
	for {
		if err := rpcConnect(t, s.fd, sockaddr); err == nil || err != syserr.ErrInProgress && err != syserr.ErrAlreadyInProgress {
			if err == nil {
				// Reset the shutdown state on new connects.
				s.resetShutdownFlags()
			}
			return err
		}

		// It's pending, so we have to wait for a notification, and fetch the
		// result once the wait completes.
		if err := t.Block(ch); err != nil {
			return syserr.FromError(err)
		}
	}
}

func rpcAccept(t *kernel.Task, fd uint32, peer bool) (*pb.AcceptResponse_ResultPayload, *syserr.Error) {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Accept{&pb.AcceptRequest{Fd: fd, Peer: peer, Flags: syscall.SOCK_NONBLOCK}}}, false /* ignoreResult */)
	<-c

	res := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Accept).Accept.Result
	if e, ok := res.(*pb.AcceptResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}
	return res.(*pb.AcceptResponse_Payload).Payload, nil
}

// Accept implements socket.Socket.Accept.
func (s *socketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (kdefs.FD, interface{}, uint32, *syserr.Error) {
	payload, se := rpcAccept(t, s.fd, peerRequested)

	// Check if we need to block.
	if blocking && se == syserr.ErrTryAgain {
		// Register for notifications.
		e, ch := waiter.NewChannelEntry(nil)
		// FIXME(b/119878986): This waiter.EventHUp is a partial
		// measure, need to figure out how to translate linux events to
		// internal events.
		s.EventRegister(&e, waiter.EventIn|waiter.EventHUp)
		defer s.EventUnregister(&e)

		// Try to accept the connection again; if it fails, then wait until we
		// get a notification.
		for {
			if payload, se = rpcAccept(t, s.fd, peerRequested); se != syserr.ErrTryAgain {
				break
			}

			if err := t.Block(ch); err != nil {
				return 0, nil, 0, syserr.FromError(err)
			}
		}
	}

	// Handle any error from accept.
	if se != nil {
		return 0, nil, 0, se
	}

	var wq waiter.Queue
	s.notifier.AddFD(payload.Fd, &wq)

	dirent := socket.NewDirent(t, socketDevice)
	defer dirent.DecRef()
	file := fs.NewFile(t, dirent, fs.FileFlags{Read: true, Write: true, NonBlocking: flags&linux.SOCK_NONBLOCK != 0}, &socketOperations{
		wq:       &wq,
		fd:       payload.Fd,
		rpcConn:  s.rpcConn,
		notifier: s.notifier,
	})
	defer file.DecRef()

	fdFlags := kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	}
	fd, err := t.FDMap().NewFDFrom(0, file, fdFlags, t.ThreadGroup().Limits())
	if err != nil {
		return 0, nil, 0, syserr.FromError(err)
	}
	t.Kernel().RecordSocket(file, s.family)

	if peerRequested {
		return fd, payload.Address.Address, payload.Address.Length, nil
	}

	return fd, nil, 0, nil
}

// Bind implements socket.Socket.Bind.
func (s *socketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Bind{&pb.BindRequest{Fd: s.fd, Address: sockaddr}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Bind).Bind.ErrorNumber; e != 0 {
		return syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

// Listen implements socket.Socket.Listen.
func (s *socketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Listen{&pb.ListenRequest{Fd: s.fd, Backlog: int64(backlog)}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Listen).Listen.ErrorNumber; e != 0 {
		return syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

// Shutdown implements socket.Socket.Shutdown.
func (s *socketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	// We save the shutdown state because of strange differences on linux
	// related to recvs on blocking vs. non-blocking sockets after a SHUT_RD.
	// We need to emulate that behavior on the blocking side.
	// TODO(b/120096741): There is a possible race that can exist with loopback,
	// where data could possibly be lost.
	s.setShutdownFlags(how)

	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Shutdown{&pb.ShutdownRequest{Fd: s.fd, How: int64(how)}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Shutdown).Shutdown.ErrorNumber; e != 0 {
		return syserr.FromHost(syscall.Errno(e))
	}

	return nil
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *socketOperations) GetSockOpt(t *kernel.Task, level int, name int, outLen int) (interface{}, *syserr.Error) {
	// SO_RCVTIMEO and SO_SNDTIMEO are special because blocking is performed
	// within the sentry.
	if level == linux.SOL_SOCKET && name == linux.SO_RCVTIMEO {
		if outLen < linux.SizeOfTimeval {
			return nil, syserr.ErrInvalidArgument
		}

		return linux.NsecToTimeval(s.RecvTimeout()), nil
	}
	if level == linux.SOL_SOCKET && name == linux.SO_SNDTIMEO {
		if outLen < linux.SizeOfTimeval {
			return nil, syserr.ErrInvalidArgument
		}

		return linux.NsecToTimeval(s.SendTimeout()), nil
	}

	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_GetSockOpt{&pb.GetSockOptRequest{Fd: s.fd, Level: int64(level), Name: int64(name), Length: uint32(outLen)}}}, false /* ignoreResult */)
	<-c

	res := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_GetSockOpt).GetSockOpt.Result
	if e, ok := res.(*pb.GetSockOptResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.GetSockOptResponse_Opt).Opt, nil
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *socketOperations) SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error {
	// Because blocking actually happens within the sentry we need to inspect
	// this socket option to determine if it's a SO_RCVTIMEO or SO_SNDTIMEO,
	// and if so, we will save it and use it as the deadline for recv(2)
	// or send(2) related syscalls.
	if level == linux.SOL_SOCKET && name == linux.SO_RCVTIMEO {
		if len(opt) < linux.SizeOfTimeval {
			return syserr.ErrInvalidArgument
		}

		var v linux.Timeval
		binary.Unmarshal(opt[:linux.SizeOfTimeval], usermem.ByteOrder, &v)
		if v.Usec < 0 || v.Usec >= int64(time.Second/time.Microsecond) {
			return syserr.ErrDomain
		}
		s.SetRecvTimeout(v.ToNsecCapped())
		return nil
	}
	if level == linux.SOL_SOCKET && name == linux.SO_SNDTIMEO {
		if len(opt) < linux.SizeOfTimeval {
			return syserr.ErrInvalidArgument
		}

		var v linux.Timeval
		binary.Unmarshal(opt[:linux.SizeOfTimeval], usermem.ByteOrder, &v)
		if v.Usec < 0 || v.Usec >= int64(time.Second/time.Microsecond) {
			return syserr.ErrDomain
		}
		s.SetSendTimeout(v.ToNsecCapped())
		return nil
	}

	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_SetSockOpt{&pb.SetSockOptRequest{Fd: s.fd, Level: int64(level), Name: int64(name), Opt: opt}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_SetSockOpt).SetSockOpt.ErrorNumber; e != 0 {
		return syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

// GetPeerName implements socket.Socket.GetPeerName.
func (s *socketOperations) GetPeerName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_GetPeerName{&pb.GetPeerNameRequest{Fd: s.fd}}}, false /* ignoreResult */)
	<-c

	res := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_GetPeerName).GetPeerName.Result
	if e, ok := res.(*pb.GetPeerNameResponse_ErrorNumber); ok {
		return nil, 0, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	addr := res.(*pb.GetPeerNameResponse_Address).Address
	return addr.Address, addr.Length, nil
}

// GetSockName implements socket.Socket.GetSockName.
func (s *socketOperations) GetSockName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_GetSockName{&pb.GetSockNameRequest{Fd: s.fd}}}, false /* ignoreResult */)
	<-c

	res := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_GetSockName).GetSockName.Result
	if e, ok := res.(*pb.GetSockNameResponse_ErrorNumber); ok {
		return nil, 0, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	addr := res.(*pb.GetSockNameResponse_Address).Address
	return addr.Address, addr.Length, nil
}

func rpcIoctl(t *kernel.Task, fd, cmd uint32, arg []byte) ([]byte, error) {
	stack := t.NetworkContext().(*Stack)

	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Ioctl{&pb.IOCtlRequest{Fd: fd, Cmd: cmd, Arg: arg}}}, false /* ignoreResult */)
	<-c

	res := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Ioctl).Ioctl.Result
	if e, ok := res.(*pb.IOCtlResponse_ErrorNumber); ok {
		return nil, syscall.Errno(e.ErrorNumber)
	}

	return res.(*pb.IOCtlResponse_Value).Value, nil
}

// ifconfIoctlFromStack populates a struct ifconf for the SIOCGIFCONF ioctl.
func ifconfIoctlFromStack(ctx context.Context, io usermem.IO, ifc *linux.IFConf) error {
	// If Ptr is NULL, return the necessary buffer size via Len.
	// Otherwise, write up to Len bytes starting at Ptr containing ifreq
	// structs.
	t := ctx.(*kernel.Task)
	s := t.NetworkContext().(*Stack)
	if s == nil {
		return syserr.ErrNoDevice.ToError()
	}

	if ifc.Ptr == 0 {
		ifc.Len = int32(len(s.Interfaces())) * int32(linux.SizeOfIFReq)
		return nil
	}

	max := ifc.Len
	ifc.Len = 0
	for key, ifaceAddrs := range s.InterfaceAddrs() {
		iface := s.Interfaces()[key]
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

// Ioctl implements fs.FileOperations.Ioctl.
func (s *socketOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	t := ctx.(*kernel.Task)

	cmd := uint32(args[1].Int())
	arg := args[2].Pointer()

	var buf []byte
	switch cmd {
	// The following ioctls take 4 byte argument parameters.
	case syscall.TIOCINQ,
		syscall.TIOCOUTQ:
		buf = make([]byte, 4)
	// The following ioctls have args which are sizeof(struct ifreq).
	case syscall.SIOCGIFADDR,
		syscall.SIOCGIFBRDADDR,
		syscall.SIOCGIFDSTADDR,
		syscall.SIOCGIFFLAGS,
		syscall.SIOCGIFHWADDR,
		syscall.SIOCGIFINDEX,
		syscall.SIOCGIFMAP,
		syscall.SIOCGIFMETRIC,
		syscall.SIOCGIFMTU,
		syscall.SIOCGIFNAME,
		syscall.SIOCGIFNETMASK,
		syscall.SIOCGIFTXQLEN:
		buf = make([]byte, linux.SizeOfIFReq)
	case syscall.SIOCGIFCONF:
		// SIOCGIFCONF has slightly different behavior than the others, in that it
		// will need to populate the array of ifreqs.
		var ifc linux.IFConf
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &ifc, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}

		if err := ifconfIoctlFromStack(ctx, io, &ifc); err != nil {
			return 0, err
		}
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), ifc, usermem.IOOpts{
			AddressSpaceActive: true,
		})

		return 0, err

	case linux.SIOCGIFMEM, linux.SIOCGIFPFLAGS, linux.SIOCGMIIPHY, linux.SIOCGMIIREG:
		unimpl.EmitUnimplementedEvent(ctx)

	default:
		return 0, syserror.ENOTTY
	}

	_, err := io.CopyIn(ctx, arg, buf, usermem.IOOpts{
		AddressSpaceActive: true,
	})

	if err != nil {
		return 0, err
	}

	v, err := rpcIoctl(t, s.fd, cmd, buf)
	if err != nil {
		return 0, err
	}

	if len(v) != len(buf) {
		return 0, syserror.EINVAL
	}

	_, err = io.CopyOut(ctx, arg, v, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	return 0, err
}

func rpcRecvMsg(t *kernel.Task, req *pb.SyscallRequest_Recvmsg) (*pb.RecvmsgResponse_ResultPayload, *syserr.Error) {
	s := t.NetworkContext().(*Stack)
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Recvmsg).Recvmsg.Result
	if e, ok := res.(*pb.RecvmsgResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.RecvmsgResponse_Payload).Payload, nil
}

// Because we only support SO_TIMESTAMP we will search control messages for
// that value and set it if so, all other control messages will be ignored.
func (s *socketOperations) extractControlMessages(payload *pb.RecvmsgResponse_ResultPayload) socket.ControlMessages {
	c := socket.ControlMessages{}
	if len(payload.GetCmsgData()) > 0 {
		// Parse the control messages looking for SO_TIMESTAMP.
		msgs, e := syscall.ParseSocketControlMessage(payload.GetCmsgData())
		if e != nil {
			return socket.ControlMessages{}
		}
		for _, m := range msgs {
			if m.Header.Level != linux.SOL_SOCKET || m.Header.Type != linux.SO_TIMESTAMP {
				continue
			}

			// Let's parse the time stamp and set it.
			if len(m.Data) < linux.SizeOfTimeval {
				// Give up on locating the SO_TIMESTAMP option.
				return socket.ControlMessages{}
			}

			var v linux.Timeval
			binary.Unmarshal(m.Data[:linux.SizeOfTimeval], usermem.ByteOrder, &v)
			c.IP.HasTimestamp = true
			c.IP.Timestamp = v.ToNsecCapped()
			break
		}
	}
	return c
}

// RecvMsg implements socket.Socket.RecvMsg.
func (s *socketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (int, int, interface{}, uint32, socket.ControlMessages, *syserr.Error) {
	req := &pb.SyscallRequest_Recvmsg{&pb.RecvmsgRequest{
		Fd:         s.fd,
		Length:     uint32(dst.NumBytes()),
		Sender:     senderRequested,
		Trunc:      flags&linux.MSG_TRUNC != 0,
		Peek:       flags&linux.MSG_PEEK != 0,
		CmsgLength: uint32(controlDataLen),
	}}

	res, err := rpcRecvMsg(t, req)
	if err == nil {
		var e error
		var n int
		if len(res.Data) > 0 {
			n, e = dst.CopyOut(t, res.Data)
			if e == nil && n != len(res.Data) {
				panic("CopyOut failed to copy full buffer")
			}
		}
		c := s.extractControlMessages(res)
		return int(res.Length), 0, res.Address.GetAddress(), res.Address.GetLength(), c, syserr.FromError(e)
	}
	if err != syserr.ErrWouldBlock && err != syserr.ErrTryAgain || flags&linux.MSG_DONTWAIT != 0 {
		return 0, 0, nil, 0, socket.ControlMessages{}, err
	}

	// We'll have to block. Register for notifications and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		res, err := rpcRecvMsg(t, req)
		if err == nil {
			var e error
			var n int
			if len(res.Data) > 0 {
				n, e = dst.CopyOut(t, res.Data)
				if e == nil && n != len(res.Data) {
					panic("CopyOut failed to copy full buffer")
				}
			}
			c := s.extractControlMessages(res)
			return int(res.Length), 0, res.Address.GetAddress(), res.Address.GetLength(), c, syserr.FromError(e)
		}
		if err != syserr.ErrWouldBlock && err != syserr.ErrTryAgain {
			return 0, 0, nil, 0, socket.ControlMessages{}, err
		}

		if s.isShutRdSet() {
			// Blocking would have caused us to block indefinitely so we return 0,
			// this is the same behavior as Linux.
			return 0, 0, nil, 0, socket.ControlMessages{}, nil
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

func rpcSendMsg(t *kernel.Task, req *pb.SyscallRequest_Sendmsg) (uint32, *syserr.Error) {
	s := t.NetworkContext().(*Stack)
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Sendmsg).Sendmsg.Result
	if e, ok := res.(*pb.SendmsgResponse_ErrorNumber); ok {
		return 0, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.SendmsgResponse_Length).Length, nil
}

// SendMsg implements socket.Socket.SendMsg.
func (s *socketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	// Whitelist flags.
	if flags&^(syscall.MSG_DONTWAIT|syscall.MSG_EOR|syscall.MSG_FASTOPEN|syscall.MSG_MORE|syscall.MSG_NOSIGNAL) != 0 {
		return 0, syserr.ErrInvalidArgument
	}

	// Reject Unix control messages.
	if !controlMessages.Unix.Empty() {
		return 0, syserr.ErrInvalidArgument
	}

	v := buffer.NewView(int(src.NumBytes()))

	// Copy all the data into the buffer.
	if _, err := src.CopyIn(t, v); err != nil {
		return 0, syserr.FromError(err)
	}

	// TODO(bgeffon): this needs to change to map directly to a SendMsg syscall
	// in the RPC.
	totalWritten := 0
	n, err := rpcSendMsg(t, &pb.SyscallRequest_Sendmsg{&pb.SendmsgRequest{
		Fd:          uint32(s.fd),
		Data:        v,
		Address:     to,
		More:        flags&linux.MSG_MORE != 0,
		EndOfRecord: flags&linux.MSG_EOR != 0,
	}})

	if err != syserr.ErrWouldBlock && err != syserr.ErrTryAgain || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), err
	}

	if n > 0 {
		totalWritten += int(n)
		v.TrimFront(int(n))
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	for {
		n, err := rpcSendMsg(t, &pb.SyscallRequest_Sendmsg{&pb.SendmsgRequest{
			Fd:          uint32(s.fd),
			Data:        v,
			Address:     to,
			More:        flags&linux.MSG_MORE != 0,
			EndOfRecord: flags&linux.MSG_EOR != 0,
		}})

		if n > 0 {
			totalWritten += int(n)
			v.TrimFront(int(n))

			if err == nil && totalWritten < int(src.NumBytes()) {
				continue
			}
		}

		if err != syserr.ErrWouldBlock && err != syserr.ErrTryAgain {
			// We eat the error in this situation.
			return int(totalWritten), nil
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return int(totalWritten), syserr.ErrTryAgain
			}
			return int(totalWritten), syserr.FromError(err)
		}
	}
}

type socketProvider struct {
	family int
}

// Socket implements socket.Provider.Socket.
func (p *socketProvider) Socket(t *kernel.Task, stypeflags transport.SockType, protocol int) (*fs.File, *syserr.Error) {
	// Check that we are using the RPC network stack.
	stack := t.NetworkContext()
	if stack == nil {
		return nil, nil
	}

	s, ok := stack.(*Stack)
	if !ok {
		return nil, nil
	}

	// Only accept TCP and UDP.
	//
	// Try to restrict the flags we will accept to minimize backwards
	// incompatibility with netstack.
	stype := int(stypeflags) & linux.SOCK_TYPE_MASK
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

	return newSocketFile(t, s, p.family, stype, 0)
}

// Pair implements socket.Provider.Pair.
func (p *socketProvider) Pair(t *kernel.Task, stype transport.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	// Not supported by AF_INET/AF_INET6.
	return nil, nil, nil
}

func init() {
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		socket.RegisterProvider(family, &socketProvider{family})
	}
}
