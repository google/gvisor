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

package rpcinet

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// socketOperations implements fs.FileOperations and socket.Socket for a socket
// implemented using a host socket.
type socketOperations struct {
	socket.ReceiveTimeout
	fsutil.PipeSeek      `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoFsync       `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoMMap        `state:"nosave"`

	fd       uint32 // must be O_NONBLOCK
	wq       *waiter.Queue
	rpcConn  *conn.RPCConnection
	notifier *notifier.Notifier
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
	if se != syserr.ErrWouldBlock {
		return 0, se.ToError()
	}

	// We'll have to block. Register for notifications and read again when ready.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		res, se := rpcRead(ctx.(*kernel.Task), req)
		if se == nil {
			n, e := dst.CopyOut(ctx, res.Data)
			return int64(n), e
		}
		if se != syserr.ErrWouldBlock {
			return 0, se.ToError()
		}

		if err := ctx.(*kernel.Task).Block(ch); err != nil {
			return 0, err
		}
	}
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
		return rpcConnect(t, s.fd, sockaddr)
	}

	// Register for notification when the endpoint becomes writable, then
	// initiate the connection.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	if err := rpcConnect(t, s.fd, sockaddr); err != syserr.ErrConnectStarted && err != syserr.ErrAlreadyConnecting {
		return err
	}

	// It's pending, so we have to wait for a notification, and fetch the
	// result once the wait completes.
	if err := t.Block(ch); err != nil {
		return syserr.FromError(err)
	}

	// Call Connect() again after blocking to find connect's result.
	return rpcConnect(t, s.fd, sockaddr)
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
	if blocking && se == syserr.ErrWouldBlock {
		// Register for notifications.
		e, ch := waiter.NewChannelEntry(nil)
		s.EventRegister(&e, waiter.EventIn)
		defer s.EventUnregister(&e)

		// Try to accept the connection again; if it fails, then wait until we
		// get a notification.
		for {
			if payload, se = rpcAccept(t, s.fd, peerRequested); se != syserr.ErrWouldBlock {
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
		notifier: s.notifier,
	})

	fdFlags := kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	}
	fd, err := t.FDMap().NewFDFrom(0, file, fdFlags, t.ThreadGroup().Limits())
	if err != nil {
		return 0, nil, 0, syserr.FromError(err)
	}

	return fd, payload.Address.Address, payload.Address.Length, nil
}

// Bind implements socket.Socket.Bind.
func (s *socketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Bind{&pb.BindRequest{Fd: s.fd, Address: sockaddr}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Bind).Bind.ErrorNumber; e != 0 {
		syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

// Listen implements socket.Socket.Listen.
func (s *socketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Listen{&pb.ListenRequest{Fd: s.fd, Backlog: int64(backlog)}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_Listen).Listen.ErrorNumber; e != 0 {
		syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

// Shutdown implements socket.Socket.Shutdown.
func (s *socketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
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
	stack := t.NetworkContext().(*Stack)
	id, c := stack.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_SetSockOpt{&pb.SetSockOptRequest{Fd: s.fd, Level: int64(level), Name: int64(name), Opt: opt}}}, false /* ignoreResult */)
	<-c

	if e := stack.rpcConn.Request(id).Result.(*pb.SyscallResponse_SetSockOpt).SetSockOpt.ErrorNumber; e != 0 {
		syserr.FromHost(syscall.Errno(e))
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

// Ioctl implements fs.FileOperations.Ioctl.
func (s *socketOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
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

// RecvMsg implements socket.Socket.RecvMsg.
func (s *socketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (int, interface{}, uint32, socket.ControlMessages, *syserr.Error) {
	req := &pb.SyscallRequest_Recvmsg{&pb.RecvmsgRequest{
		Fd:     s.fd,
		Length: uint32(dst.NumBytes()),
		Sender: senderRequested,
		Trunc:  flags&linux.MSG_TRUNC != 0,
		Peek:   flags&linux.MSG_PEEK != 0,
	}}

	res, err := rpcRecvMsg(t, req)
	if err == nil {
		n, e := dst.CopyOut(t, res.Data)
		return int(n), res.Address.GetAddress(), res.Address.GetLength(), socket.ControlMessages{}, syserr.FromError(e)
	}
	if err != syserr.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return 0, nil, 0, socket.ControlMessages{}, err
	}

	// We'll have to block. Register for notifications and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		res, err := rpcRecvMsg(t, req)
		if err == nil {
			n, e := dst.CopyOut(t, res.Data)
			return int(n), res.Address.GetAddress(), res.Address.GetLength(), socket.ControlMessages{}, syserr.FromError(e)
		}
		if err != syserr.ErrWouldBlock {
			return 0, nil, 0, socket.ControlMessages{}, err
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
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
func (s *socketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, controlMessages socket.ControlMessages) (int, *syserr.Error) {
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

	// TODO: this needs to change to map directly to a SendMsg syscall
	// in the RPC.
	req := &pb.SyscallRequest_Sendmsg{&pb.SendmsgRequest{
		Fd:          uint32(s.fd),
		Data:        v,
		Address:     to,
		More:        flags&linux.MSG_MORE != 0,
		EndOfRecord: flags&linux.MSG_EOR != 0,
	}}

	n, err := rpcSendMsg(t, req)
	if err != syserr.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), err
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	for {
		n, err := rpcSendMsg(t, req)
		if err != syserr.ErrWouldBlock {
			return int(n), err
		}

		if err := t.Block(ch); err != nil {
			return 0, syserr.FromError(err)
		}
	}
}

type socketProvider struct {
	family int
}

// Socket implements socket.Provider.Socket.
func (p *socketProvider) Socket(t *kernel.Task, stypeflags unix.SockType, protocol int) (*fs.File, *syserr.Error) {
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
func (p *socketProvider) Pair(t *kernel.Task, stype unix.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	// Not supported by AF_INET/AF_INET6.
	return nil, nil, nil
}

func init() {
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		socket.RegisterProvider(family, &socketProvider{family})
	}
}
