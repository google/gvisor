// Copyright 2021 The gVisor Authors.
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

package transport

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SCMRights implements RightsControlMessage with host FDs.
type SCMRights struct {
	FDs []int
}

// Clone implements RightsControlMessage.Clone.
func (c *SCMRights) Clone() RightsControlMessage {
	// Host rights never need to be cloned.
	return nil
}

// TransferRights implements RightsControlMessage.TransferRights.
func (c *SCMRights) TransferRights() RightsControlMessage {
	nc := &SCMRights{FDs: c.FDs}
	c.FDs = nil
	return nc
}

// Release implements RightsControlMessage.Release.
func (c *SCMRights) Release(ctx context.Context) {
	for _, fd := range c.FDs {
		unix.Close(fd)
	}
	c.FDs = nil
}

// HostSender is an implementation of Sender and
// Receiver. It is backed by a host fd that was imported at sentry startup.
// This fd is shared with a hostfs inode, which retains ownership of it.
//
// HostSender is saveable, since we expect that the host will
// provide the same fd upon restore.
//
// As of this writing, we only allow Unix sockets to be imported.
//
// +stateify savable
type HostSender struct {
	HostSenderRefs

	// mu protects fd below.
	mu sync.RWMutex `state:"nosave"`

	// fd is the host fd backing this endpoint.
	fd int

	// addr is the address at which this endpoint is bound.
	addr string

	// sndbuf is the size of the send buffer.
	//
	// N.B. When this is smaller than the host size, we present it via
	// GetSockOpt and message splitting/rejection in SendMsg, but do not
	// prevent lots of small messages from filling the real send buffer
	// size on the host.
	sndbuf atomicbitops.Int64 `state:"nosave"`

	// stype is the type of Unix socket.
	stype linux.SockType

	// recvShutdown is true if receptions have been shutdown with SHUT_RD.
	recvShutdown atomicbitops.Bool

	// sendShutdown is true if transmissions have been shutdown with SHUT_WR.
	sendShutdown atomicbitops.Bool

	// passcred is true if SO_PASSCRED is enabled on the host socket.
	passcred bool
}

// init performs initialization required for creating new
// HostSenders and for restoring them.
func (c *HostSender) init() *syserr.Error {
	c.InitRefs()
	return c.initFromOptions()
}

func (c *HostSender) initFromOptions() *syserr.Error {
	if c.fd < 0 {
		// There is no underlying FD to restore; nothing to do
		return nil
	}

	family, err := unix.GetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return syserr.FromError(err)
	}

	if family != unix.AF_UNIX {
		// We only allow Unix sockets.
		return syserr.ErrInvalidEndpointState
	}

	stype, err := unix.GetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return syserr.FromError(err)
	}

	if err := unix.SetNonblock(c.fd, true); err != nil {
		return syserr.FromError(err)
	}

	sndbuf, err := unix.GetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		return syserr.FromError(err)
	}

	passcred, err := unix.GetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_PASSCRED)
	if err != nil {
		return syserr.FromError(err)
	}

	c.stype = linux.SockType(stype)
	c.sndbuf.Store(int64(sndbuf))
	c.passcred = passcred != 0

	return nil
}

// NewHostSender creates a new HostSender backed by a
// host fd imported at sentry startup.
//
// The caller is responsible for calling Init(). Additionally, Release needs to
// be called twice because HostSender is both a Receiver and
// HostSender.
func NewHostSender(hostFD int, addr string) (*HostSender, *syserr.Error) {
	e := HostSender{
		fd:   hostFD,
		addr: addr,
	}

	if err := e.init(); err != nil {
		return nil, err
	}

	// HostSenderRefs start off with a single reference. We need two.
	e.IncRef()
	return &e, nil
}

// SockType returns the underlying socket type.
func (c *HostSender) SockType() linux.SockType {
	return c.stype
}

// Send implements Sender.Send.
func (c *HostSender) Send(ctx context.Context, data [][]byte, controlMessages ControlMessages, from Address) (int64, bool, *syserr.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if controlMessages.Rights != nil {
		return 0, false, syserr.ErrInvalidEndpointState
	}

	if c.IsSendClosed() {
		return 0, false, syserr.ErrClosedForSend
	}

	// Since stream sockets don't preserve message boundaries, we can write
	// only as much of the message as fits in the send buffer.
	truncate := c.stype == linux.SOCK_STREAM

	n, totalLen, err := fdWriteVec(c.fd, data, c.SendMaxQueueSize(), truncate, controlMessages.Credentials != nil)
	if n < totalLen && err == nil {
		// The host only returns a short write if it would otherwise
		// block (and only for stream sockets).
		err = linuxerr.EAGAIN
	}
	if n > 0 && !linuxerr.Equals(linuxerr.EAGAIN, err) {
		// The caller may need to block to send more data, but
		// otherwise there isn't anything that can be done about an
		// error with a partial write.
		err = nil
	}

	// There is no need for the callee to call NotifyDataReady because fdWriteVec
	// uses the host's sendmsg(2) and the host kernel's queue.
	return n, false, syserr.FromError(err)
}

// NotifyDataReady implements Sender.NotifyDataReady.
func (c *HostSender) NotifyDataReady() {}

// CloseSend implements Sender.CloseSend.
func (c *HostSender) CloseSend() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeSendLocked()
}

// Preconditions: c.mu must be held.
func (c *HostSender) closeSendLocked() {
	if c.IsSendClosed() {
		return
	}

	if err := unix.Shutdown(c.fd, unix.SHUT_WR); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed write shutdown on host socket %+v: %v", c, err))
	}
	c.sendShutdown.Store(true)
}

// NotifyStateChange implements Sender.NotifyStateChange.
func (c *HostSender) NotifyStateChange() {}

// IsSendClosed implements ConnectedEndpoint.IsSendClosed.
func (c *HostSender) IsSendClosed() bool {
	return c.sendShutdown.Load()
}

// Writable implements Sender.Writable.
func (c *HostSender) Writable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.fd), waiter.WritableEvents)&waiter.WritableEvents != 0
}

// Passcred implements Sender.Passcred.
func (c *HostSender) Passcred() bool {
	return c.passcred
}

// GetLocalAddress implements Sender.GetLocalAddress.
func (c *HostSender) GetLocalAddress() (Address, tcpip.Error) {
	return Address{Addr: c.addr}, nil
}

// EventUpdate implements Sender.EventUpdate.
func (c *HostSender) EventUpdate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.fd != -1 {
		if err := fdnotifier.UpdateFD(int32(c.fd)); err != nil {
			return err
		}
	}
	return nil
}

// Recv implements Receiver.Recv.
func (c *HostSender) Recv(ctx context.Context, data [][]byte, args RecvArgs) (RecvOutput, bool, *syserr.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var cm unet.ControlMessage
	if args.NumRights > 0 {
		cm.EnableFDs(int(args.NumRights))
	}

	// N.B. Unix sockets don't have a receive buffer, the send buffer
	// serves both purposes.
	//
	// We ignore args.Creds because we don't translate sandbox socket options to
	// host socket options, so the fd won't have the SO_PASSCRED option set. By
	// default, the sentry will always return credentials with PID 0 and UID/GID
	// 65534 (nobody).
	out := RecvOutput{Source: Address{Addr: c.addr}}
	var err error
	var controlLen uint64
	out.RecvLen, out.MsgLen, controlLen, out.ControlTrunc, err = fdReadVec(c.fd, data, []byte(cm), args.Peek, c.RecvMaxQueueSize())
	if out.RecvLen > 0 && err != nil {
		// We got some data, so all we need to do on error is return
		// the data that we got. Short reads are fine, no need to
		// block.
		err = nil
	}
	if err != nil {
		return RecvOutput{}, false, syserr.FromError(err)
	}

	// There is no need for the callee to call NotifyWriteSpace because fdReadVec uses
	// the host's recvmsg(2) and the host kernel's queue.

	// Trim the control data if we received less than the full amount.
	if controlLen < uint64(len(cm)) {
		cm = cm[:controlLen]
	}

	// Avoid extra allocations in the case where there isn't any control data.
	if len(cm) == 0 {
		return out, false, nil
	}

	fds, err := cm.ExtractFDs()
	if err != nil {
		return RecvOutput{}, false, syserr.FromError(err)
	}

	if len(fds) == 0 {
		return out, false, nil
	}
	out.Control = ControlMessages{
		Rights: &SCMRights{fds},
	}
	return out, false, nil
}

// NotifyWriteSpace implements Receiver.NotifyWriteSpace.
func (c *HostSender) NotifyWriteSpace() {}

// CloseRecv implements Receiver.CloseRecv.
func (c *HostSender) CloseRecv() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeRecvLocked()
}

// Preconditions: c.mu must be held.
func (c *HostSender) closeRecvLocked() {
	if c.IsRecvClosed() {
		return
	}

	if err := unix.Shutdown(c.fd, unix.SHUT_RD); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed read shutdown on host socket %+v: %v", c, err))
	}
	c.recvShutdown.Store(true)
}

// IsRecvClosed implements Receiver.IsRecvClosed.
func (c *HostSender) IsRecvClosed() bool {
	return c.recvShutdown.Load()
}

// HostReadiness implements HostReadiness.HostReadiness.
func (c *HostSender) HostReadiness(mask waiter.EventMask) waiter.EventMask {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.fd < 0 {
		return 0
	}
	return fdnotifier.NonBlockingPoll(int32(c.fd), mask)
}

// Readable implements Receiver.Readable.
func (c *HostSender) Readable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.fd), waiter.ReadableEvents)&waiter.ReadableEvents != 0
}

// SendQueuedSize implements Receiver.SendQueuedSize.
func (c *HostSender) SendQueuedSize() int64 {
	// TODO(gvisor.dev/issue/273): SendQueuedSize isn't supported for host
	// sockets because we don't allow the sentry to call ioctl(2).
	return -1
}

// RecvQueuedSize implements Receiver.RecvQueuedSize.
func (c *HostSender) RecvQueuedSize() int64 {
	// TODO(gvisor.dev/issue/273): RecvQueuedSize isn't supported for host
	// sockets because we don't allow the sentry to call ioctl(2).
	return -1
}

// SendMaxQueueSize implements Receiver.SendMaxQueueSize.
func (c *HostSender) SendMaxQueueSize() int64 {
	return c.sndbuf.Load()
}

// RecvMaxQueueSize implements Receiver.RecvMaxQueueSize.
func (c *HostSender) RecvMaxQueueSize() int64 {
	// N.B. Unix sockets don't use the receive buffer. We'll claim it is
	// the same size as the send buffer.
	return c.sndbuf.Load()
}

func (c *HostSender) destroyLocked() {
	c.fd = -1
}

// Release implements Sender.Release and Receiver.Release.
func (c *HostSender) Release(ctx context.Context) {
	c.DecRef(func() {
		c.mu.Lock()
		c.destroyLocked()
		c.mu.Unlock()
	})
}

// CloseUnread implements Sender.CloseUnread.
func (c *HostSender) CloseUnread() {}

// SetSendBufferSize implements Sender.SetSendBufferSize.
func (c *HostSender) SetSendBufferSize(v int64) (newSz int64) {
	// gVisor does not permit setting of SO_SNDBUF for host backed unix
	// domain sockets.
	return c.sndbuf.Load()
}

// SetReceiveBufferSize implements Sender.SetReceiveBufferSize.
func (c *HostSender) SetReceiveBufferSize(v int64) (newSz int64) {
	// gVisor does not permit setting of SO_RCVBUF for host backed unix
	// domain sockets. Receive buffer does not have any effect for unix
	// sockets and we claim to be the same as send buffer.
	return c.sndbuf.Load()
}

// SCMSender represents an endpoint backed by a host fd that was
// passed through a gofer Unix socket. It resembles HostSender, with the
// following differences:
//   - SCMSender is not saveable by default, because the host
//     cannot guarantee the same descriptor number across S/R.
//     However, it can optionally be placed in a closed state before save.
//   - SCMSender holds ownership of its fd and notification queue.
//
// +stateify savable
type SCMSender struct {
	HostSender

	queue *waiter.Queue
}

// beforeSave is invoked by stateify.
func (e *SCMSender) beforeSave() {
	e.mu.Lock()
	defer e.mu.Unlock()
	fdnotifier.RemoveFD(int32(e.fd))
	e.closeRecvLocked()
	e.closeSendLocked()
	if err := unix.Close(e.fd); err != nil {
		log.Warningf("Failed to close host fd %d: %v", e.fd, err)
	}
	e.destroyLocked()
}

// Init will do the initialization required without holding other locks.
func (e *SCMSender) Init() error {
	return fdnotifier.AddFD(int32(e.fd), e.queue)
}

// Release implements Sender.Release and Receiver.Release.
func (e *SCMSender) Release(ctx context.Context) {
	e.DecRef(func() {
		e.mu.Lock()
		defer e.mu.Unlock()

		if e.fd < 0 {
			return
		}

		fdnotifier.RemoveFD(int32(e.fd))
		if err := unix.Close(e.fd); err != nil {
			log.Warningf("Failed to close host fd %d: %v", e.fd, err)
		}
		e.destroyLocked()
	})
}

// NewSCMSender creates a new SCMSender backed by a host fd that
// was passed through a Unix socket.
//
// The caller is responsible for calling Init(). Additionally, Release needs to
// be called twice because Sender is both a Receiver and
// Sender.
func NewSCMSender(hostFD int, queue *waiter.Queue, addr string) (*SCMSender, *syserr.Error) {
	e := SCMSender{
		HostSender: HostSender{
			fd:   hostFD,
			addr: addr,
		},
		queue: queue,
	}

	if err := e.init(); err != nil {
		return nil, err
	}

	// e starts off with a single reference. We need two.
	e.IncRef()
	return &e, nil
}
