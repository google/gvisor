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

// Package netlink provides core functionality for netlink sockets.
package netlink

import (
	"math"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/port"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

const sizeOfInt32 int = 4

const (
	// minBufferSize is the smallest size of a send buffer.
	minSendBufferSize = 4 << 10 // 4096 bytes.

	// defaultSendBufferSize is the default size for the send buffer.
	defaultSendBufferSize = 16 * 1024

	// maxBufferSize is the largest size a send buffer can grow to.
	maxSendBufferSize = 4 << 20 // 4MB
)

// netlinkSocketDevice is the netlink socket virtual device.
var netlinkSocketDevice = device.NewAnonDevice()

// Socket is the base socket type for netlink sockets.
//
// This implementation only supports userspace sending and receiving messages
// to/from the kernel.
//
// Socket implements socket.Socket and transport.Credentialer.
//
// +stateify savable
type Socket struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	socket.SendReceiveTimeout

	// ports provides netlink port allocation.
	ports *port.Manager

	// protocol is the netlink protocol implementation.
	protocol Protocol

	// skType is the socket type. This is either SOCK_DGRAM or SOCK_RAW for
	// netlink sockets.
	skType linux.SockType

	// ep is a datagram unix endpoint used to buffer messages sent from the
	// kernel to userspace. RecvMsg reads messages from this endpoint.
	ep transport.Endpoint

	// connection is the kernel's connection to ep, used to write messages
	// sent to userspace.
	connection transport.ConnectedEndpoint

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// bound indicates that portid is valid.
	bound bool

	// portID is the port ID allocated for this socket.
	portID int32

	// sendBufferSize is the send buffer "size". We don't actually have a
	// fixed buffer but only consume this many bytes.
	sendBufferSize uint32

	// passcred indicates if this socket wants SCM credentials.
	passcred bool
}

var _ socket.Socket = (*Socket)(nil)
var _ transport.Credentialer = (*Socket)(nil)

// NewSocket creates a new Socket.
func NewSocket(t *kernel.Task, skType linux.SockType, protocol Protocol) (*Socket, *syserr.Error) {
	// Datagram endpoint used to buffer kernel -> user messages.
	ep := transport.NewConnectionless(t)

	// Bind the endpoint for good measure so we can connect to it. The
	// bound address will never be exposed.
	if err := ep.Bind(tcpip.FullAddress{Addr: "dummy"}, nil); err != nil {
		ep.Close()
		return nil, err
	}

	// Create a connection from which the kernel can write messages.
	connection, err := ep.(transport.BoundEndpoint).UnidirectionalConnect(t)
	if err != nil {
		ep.Close()
		return nil, err
	}

	return &Socket{
		ports:          t.Kernel().NetlinkPorts(),
		protocol:       protocol,
		skType:         skType,
		ep:             ep,
		connection:     connection,
		sendBufferSize: defaultSendBufferSize,
	}, nil
}

// Release implements fs.FileOperations.Release.
func (s *Socket) Release() {
	s.connection.Release()
	s.ep.Close()

	if s.bound {
		s.ports.Release(s.protocol.Protocol(), s.portID)
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (s *Socket) Readiness(mask waiter.EventMask) waiter.EventMask {
	// ep holds messages to be read and thus handles EventIn readiness.
	ready := s.ep.Readiness(mask)

	if mask&waiter.EventOut == waiter.EventOut {
		// sendMsg handles messages synchronously and is thus always
		// ready for writing.
		ready |= waiter.EventOut
	}

	return ready
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *Socket) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.ep.EventRegister(e, mask)
	// Writable readiness never changes, so no registration is needed.
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *Socket) EventUnregister(e *waiter.Entry) {
	s.ep.EventUnregister(e)
}

// Passcred implements transport.Credentialer.Passcred.
func (s *Socket) Passcred() bool {
	s.mu.Lock()
	passcred := s.passcred
	s.mu.Unlock()
	return passcred
}

// ConnectedPasscred implements transport.Credentialer.ConnectedPasscred.
func (s *Socket) ConnectedPasscred() bool {
	// This socket is connected to the kernel, which doesn't need creds.
	//
	// This is arbitrary, as ConnectedPasscred on this type has no callers.
	return false
}

// Ioctl implements fs.FileOperations.Ioctl.
func (*Socket) Ioctl(context.Context, *fs.File, usermem.IO, arch.SyscallArguments) (uintptr, error) {
	// TODO(b/68878065): no ioctls supported.
	return 0, syserror.ENOTTY
}

// ExtractSockAddr extracts the SockAddrNetlink from b.
func ExtractSockAddr(b []byte) (*linux.SockAddrNetlink, *syserr.Error) {
	if len(b) < linux.SockAddrNetlinkSize {
		return nil, syserr.ErrBadAddress
	}

	var sa linux.SockAddrNetlink
	binary.Unmarshal(b[:linux.SockAddrNetlinkSize], usermem.ByteOrder, &sa)

	if sa.Family != linux.AF_NETLINK {
		return nil, syserr.ErrInvalidArgument
	}

	return &sa, nil
}

// bindPort binds this socket to a port, preferring 'port' if it is available.
//
// port of 0 defaults to the ThreadGroup ID.
//
// Preconditions: mu is held.
func (s *Socket) bindPort(t *kernel.Task, port int32) *syserr.Error {
	if s.bound {
		// Re-binding is only allowed if the port doesn't change.
		if port != s.portID {
			return syserr.ErrInvalidArgument
		}

		return nil
	}

	if port == 0 {
		port = int32(t.ThreadGroup().ID())
	}
	port, ok := s.ports.Allocate(s.protocol.Protocol(), port)
	if !ok {
		return syserr.ErrBusy
	}

	s.portID = port
	s.bound = true
	return nil
}

// Bind implements socket.Socket.Bind.
func (s *Socket) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	a, err := ExtractSockAddr(sockaddr)
	if err != nil {
		return err
	}

	// No support for multicast groups yet.
	if a.Groups != 0 {
		return syserr.ErrPermissionDenied
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.bindPort(t, int32(a.PortID))
}

// Connect implements socket.Socket.Connect.
func (s *Socket) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	a, err := ExtractSockAddr(sockaddr)
	if err != nil {
		return err
	}

	// No support for multicast groups yet.
	if a.Groups != 0 {
		return syserr.ErrPermissionDenied
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if a.PortID == 0 {
		// Netlink sockets default to connected to the kernel, but
		// connecting anyways automatically binds if not already bound.
		if !s.bound {
			// Pass port 0 to get an auto-selected port ID.
			return s.bindPort(t, 0)
		}
		return nil
	}

	// We don't support non-kernel destination ports. Linux returns EPERM
	// if applications attempt to do this without NL_CFG_F_NONROOT_SEND, so
	// we emulate that.
	return syserr.ErrPermissionDenied
}

// Accept implements socket.Socket.Accept.
func (s *Socket) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	// Netlink sockets never support accept.
	return 0, nil, 0, syserr.ErrNotSupported
}

// Listen implements socket.Socket.Listen.
func (s *Socket) Listen(t *kernel.Task, backlog int) *syserr.Error {
	// Netlink sockets never support listen.
	return syserr.ErrNotSupported
}

// Shutdown implements socket.Socket.Shutdown.
func (s *Socket) Shutdown(t *kernel.Task, how int) *syserr.Error {
	// Netlink sockets never support shutdown.
	return syserr.ErrNotSupported
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *Socket) GetSockOpt(t *kernel.Task, level int, name int, outPtr usermem.Addr, outLen int) (interface{}, *syserr.Error) {
	switch level {
	case linux.SOL_SOCKET:
		switch name {
		case linux.SO_SNDBUF:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			return int32(s.sendBufferSize), nil

		case linux.SO_RCVBUF:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}
			// We don't have limit on receiving size.
			return int32(math.MaxInt32), nil

		case linux.SO_PASSCRED:
			if outLen < sizeOfInt32 {
				return nil, syserr.ErrInvalidArgument
			}
			var passcred int32
			if s.Passcred() {
				passcred = 1
			}
			return passcred, nil

		default:
			socket.GetSockOptEmitUnimplementedEvent(t, name)
		}

	case linux.SOL_NETLINK:
		switch name {
		case linux.NETLINK_BROADCAST_ERROR,
			linux.NETLINK_CAP_ACK,
			linux.NETLINK_DUMP_STRICT_CHK,
			linux.NETLINK_EXT_ACK,
			linux.NETLINK_LIST_MEMBERSHIPS,
			linux.NETLINK_NO_ENOBUFS,
			linux.NETLINK_PKTINFO:

			t.Kernel().EmitUnimplementedEvent(t)
		}
	}
	// TODO(b/68878065): other sockopts are not supported.
	return nil, syserr.ErrProtocolNotAvailable
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *Socket) SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error {
	switch level {
	case linux.SOL_SOCKET:
		switch name {
		case linux.SO_SNDBUF:
			if len(opt) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}
			size := usermem.ByteOrder.Uint32(opt)
			if size < minSendBufferSize {
				size = minSendBufferSize
			} else if size > maxSendBufferSize {
				size = maxSendBufferSize
			}
			s.mu.Lock()
			s.sendBufferSize = size
			s.mu.Unlock()
			return nil

		case linux.SO_RCVBUF:
			if len(opt) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}
			// We don't have limit on receiving size. So just accept anything as
			// valid for compatibility.
			return nil

		case linux.SO_PASSCRED:
			if len(opt) < sizeOfInt32 {
				return syserr.ErrInvalidArgument
			}
			passcred := usermem.ByteOrder.Uint32(opt)

			s.mu.Lock()
			s.passcred = passcred != 0
			s.mu.Unlock()
			return nil

		default:
			socket.SetSockOptEmitUnimplementedEvent(t, name)
		}

	case linux.SOL_NETLINK:
		switch name {
		case linux.NETLINK_ADD_MEMBERSHIP,
			linux.NETLINK_BROADCAST_ERROR,
			linux.NETLINK_CAP_ACK,
			linux.NETLINK_DROP_MEMBERSHIP,
			linux.NETLINK_DUMP_STRICT_CHK,
			linux.NETLINK_EXT_ACK,
			linux.NETLINK_LISTEN_ALL_NSID,
			linux.NETLINK_NO_ENOBUFS,
			linux.NETLINK_PKTINFO:

			t.Kernel().EmitUnimplementedEvent(t)
		}

	}
	// TODO(b/68878065): other sockopts are not supported.
	return syserr.ErrProtocolNotAvailable
}

// GetSockName implements socket.Socket.GetSockName.
func (s *Socket) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sa := &linux.SockAddrNetlink{
		Family: linux.AF_NETLINK,
		PortID: uint32(s.portID),
	}
	return sa, uint32(binary.Size(sa)), nil
}

// GetPeerName implements socket.Socket.GetPeerName.
func (s *Socket) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	sa := &linux.SockAddrNetlink{
		Family: linux.AF_NETLINK,
		// TODO(b/68878065): Support non-kernel peers. For now the peer
		// must be the kernel.
		PortID: 0,
	}
	return sa, uint32(binary.Size(sa)), nil
}

// RecvMsg implements socket.Socket.RecvMsg.
func (s *Socket) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	from := &linux.SockAddrNetlink{
		Family: linux.AF_NETLINK,
		PortID: 0,
	}
	fromLen := uint32(binary.Size(from))

	trunc := flags&linux.MSG_TRUNC != 0

	r := unix.EndpointReader{
		Endpoint: s.ep,
		Peek:     flags&linux.MSG_PEEK != 0,
	}

	// If MSG_TRUNC is set with a zero byte destination then we still need
	// to read the message and discard it, or in the case where MSG_PEEK is
	// set, leave it be. In both cases the full message length must be
	// returned. However, the memory manager for the destination will not read
	// the endpoint if the destination is zero length.
	//
	// In order for the endpoint to be read when the destination size is zero,
	// we must cause a read of the endpoint by using a separate fake zero
	// length block sequence and calling the EndpointReader directly.
	if trunc && dst.Addrs.NumBytes() == 0 {
		// Perform a read to a zero byte block sequence. We can ignore the
		// original destination since it was zero bytes. The length returned by
		// ReadToBlocks is ignored and we return the full message length to comply
		// with MSG_TRUNC.
		_, err := r.ReadToBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(make([]byte, 0))))
		return int(r.MsgSize), linux.MSG_TRUNC, from, fromLen, socket.ControlMessages{}, syserr.FromError(err)
	}

	if n, err := dst.CopyOutFrom(t, &r); err != syserror.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		var mflags int
		if n < int64(r.MsgSize) {
			mflags |= linux.MSG_TRUNC
		}
		if trunc {
			n = int64(r.MsgSize)
		}
		return int(n), mflags, from, fromLen, socket.ControlMessages{}, syserr.FromError(err)
	}

	// We'll have to block. Register for notification and keep trying to
	// receive all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		if n, err := dst.CopyOutFrom(t, &r); err != syserror.ErrWouldBlock {
			var mflags int
			if n < int64(r.MsgSize) {
				mflags |= linux.MSG_TRUNC
			}
			if trunc {
				n = int64(r.MsgSize)
			}
			return int(n), mflags, from, fromLen, socket.ControlMessages{}, syserr.FromError(err)
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

// Read implements fs.FileOperations.Read.
func (s *Socket) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	return dst.CopyOutFrom(ctx, &unix.EndpointReader{
		Endpoint: s.ep,
	})
}

// kernelSCM implements control.SCMCredentials with credentials that represent
// the kernel itself rather than a Task.
//
// +stateify savable
type kernelSCM struct{}

// Equals implements transport.CredentialsControlMessage.Equals.
func (kernelSCM) Equals(oc transport.CredentialsControlMessage) bool {
	_, ok := oc.(kernelSCM)
	return ok
}

// Credentials implements control.SCMCredentials.Credentials.
func (kernelSCM) Credentials(*kernel.Task) (kernel.ThreadID, auth.UID, auth.GID) {
	return 0, auth.RootUID, auth.RootGID
}

// kernelCreds is the concrete version of kernelSCM used in all creds.
var kernelCreds = &kernelSCM{}

// sendResponse sends the response messages in ms back to userspace.
func (s *Socket) sendResponse(ctx context.Context, ms *MessageSet) *syserr.Error {
	// Linux combines multiple netlink messages into a single datagram.
	bufs := make([][]byte, 0, len(ms.Messages))
	for _, m := range ms.Messages {
		bufs = append(bufs, m.Finalize())
	}

	// All messages are from the kernel.
	cms := transport.ControlMessages{
		Credentials: kernelCreds,
	}

	if len(bufs) > 0 {
		// RecvMsg never receives the address, so we don't need to send
		// one.
		_, notify, err := s.connection.Send(bufs, cms, tcpip.FullAddress{})
		// If the buffer is full, we simply drop messages, just like
		// Linux.
		if err != nil && err != syserr.ErrWouldBlock {
			return err
		}
		if notify {
			s.connection.SendNotify()
		}
	}

	// N.B. multi-part messages should still send NLMSG_DONE even if
	// MessageSet contains no messages.
	//
	// N.B. NLMSG_DONE is always sent in a different datagram. See
	// net/netlink/af_netlink.c:netlink_dump.
	if ms.Multi {
		m := NewMessage(linux.NetlinkMessageHeader{
			Type:   linux.NLMSG_DONE,
			Flags:  linux.NLM_F_MULTI,
			Seq:    ms.Seq,
			PortID: uint32(ms.PortID),
		})

		// Add the dump_done_errno payload.
		m.Put(int64(0))

		_, notify, err := s.connection.Send([][]byte{m.Finalize()}, cms, tcpip.FullAddress{})
		if err != nil && err != syserr.ErrWouldBlock {
			return err
		}
		if notify {
			s.connection.SendNotify()
		}
	}

	return nil
}

func (s *Socket) dumpErrorMesage(ctx context.Context, hdr linux.NetlinkMessageHeader, ms *MessageSet, err *syserr.Error) *syserr.Error {
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: linux.NLMSG_ERROR,
	})

	m.Put(linux.NetlinkErrorMessage{
		Error:  int32(-err.ToLinux().Number()),
		Header: hdr,
	})
	return nil

}

// processMessages handles each message in buf, passing it to the protocol
// handler for final handling.
func (s *Socket) processMessages(ctx context.Context, buf []byte) *syserr.Error {
	for len(buf) > 0 {
		if len(buf) < linux.NetlinkMessageHeaderSize {
			// Linux ignores messages that are too short. See
			// net/netlink/af_netlink.c:netlink_rcv_skb.
			break
		}

		var hdr linux.NetlinkMessageHeader
		binary.Unmarshal(buf[:linux.NetlinkMessageHeaderSize], usermem.ByteOrder, &hdr)

		if hdr.Length < linux.NetlinkMessageHeaderSize || uint64(hdr.Length) > uint64(len(buf)) {
			// Linux ignores malformed messages. See
			// net/netlink/af_netlink.c:netlink_rcv_skb.
			break
		}

		// Data from this message.
		data := buf[linux.NetlinkMessageHeaderSize:hdr.Length]

		// Advance to the next message.
		next := alignUp(int(hdr.Length), linux.NLMSG_ALIGNTO)
		if next >= len(buf)-1 {
			next = len(buf) - 1
		}
		buf = buf[next:]

		// Ignore control messages.
		if hdr.Type < linux.NLMSG_MIN_TYPE {
			continue
		}

		ms := NewMessageSet(s.portID, hdr.Seq)
		var err *syserr.Error
		// TODO(b/68877377): ACKs not supported yet.
		if hdr.Flags&linux.NLM_F_ACK == linux.NLM_F_ACK {
			err = syserr.ErrNotSupported
		} else {

			err = s.protocol.ProcessMessage(ctx, hdr, data, ms)
		}
		if err != nil {
			ms = NewMessageSet(s.portID, hdr.Seq)
			if err := s.dumpErrorMesage(ctx, hdr, ms, err); err != nil {
				return err
			}
		}

		if err := s.sendResponse(ctx, ms); err != nil {
			return err
		}
	}

	return nil
}

// sendMsg is the core of message send, used for SendMsg and Write.
func (s *Socket) sendMsg(ctx context.Context, src usermem.IOSequence, to []byte, flags int, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	dstPort := int32(0)

	if len(to) != 0 {
		a, err := ExtractSockAddr(to)
		if err != nil {
			return 0, err
		}

		// No support for multicast groups yet.
		if a.Groups != 0 {
			return 0, syserr.ErrPermissionDenied
		}

		dstPort = int32(a.PortID)
	}

	if dstPort != 0 {
		// Non-kernel destinations not supported yet. Treat as if
		// NL_CFG_F_NONROOT_SEND is not set.
		return 0, syserr.ErrPermissionDenied
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// For simplicity, and consistency with Linux, we copy in the entire
	// message up front.
	if src.NumBytes() > int64(s.sendBufferSize) {
		return 0, syserr.ErrMessageTooLong
	}

	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		// Don't partially consume messages.
		return 0, syserr.FromError(err)
	}

	if err := s.processMessages(ctx, buf); err != nil {
		return 0, err
	}

	return n, nil
}

// SendMsg implements socket.Socket.SendMsg.
func (s *Socket) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	return s.sendMsg(t, src, to, flags, controlMessages)
}

// Write implements fs.FileOperations.Write.
func (s *Socket) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	n, err := s.sendMsg(ctx, src, nil, 0, socket.ControlMessages{})
	return int64(n), err.ToError()
}

// State implements socket.Socket.State.
func (s *Socket) State() uint32 {
	return s.ep.State()
}

// Type implements socket.Socket.Type.
func (s *Socket) Type() (family int, skType linux.SockType, protocol int) {
	return linux.AF_NETLINK, s.skType, s.protocol.Protocol()
}
