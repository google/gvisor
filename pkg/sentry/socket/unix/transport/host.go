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

// Release implements RightsControlMessage.Release.
func (c *SCMRights) Release(ctx context.Context) {
	for _, fd := range c.FDs {
		unix.Close(fd)
	}
	c.FDs = nil
}

// HostConnectedEndpoint is an implementation of ConnectedEndpoint and
// Receiver. It is backed by a host fd that was imported at sentry startup.
// This fd is shared with a hostfs inode, which retains ownership of it.
//
// HostConnectedEndpoint is saveable, since we expect that the host will
// provide the same fd upon restore.
//
// As of this writing, we only allow Unix sockets to be imported.
//
// +stateify savable
type HostConnectedEndpoint struct {
	HostConnectedEndpointRefs

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
}

// init performs initialization required for creating new
// HostConnectedEndpoints and for restoring them.
func (c *HostConnectedEndpoint) init() *syserr.Error {
	c.InitRefs()
	return c.initFromOptions()
}

func (c *HostConnectedEndpoint) initFromOptions() *syserr.Error {
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

	c.stype = linux.SockType(stype)
	c.sndbuf.Store(int64(sndbuf))

	return nil
}

// NewHostConnectedEndpoint creates a new HostConnectedEndpoint backed by a
// host fd imported at sentry startup.
//
// The caller is responsible for calling Init(). Additionally, Release needs to
// be called twice because HostConnectedEndpoint is both a Receiver and
// HostConnectedEndpoint.
func NewHostConnectedEndpoint(hostFD int, addr string) (*HostConnectedEndpoint, *syserr.Error) {
	e := HostConnectedEndpoint{
		fd:   hostFD,
		addr: addr,
	}

	if err := e.init(); err != nil {
		return nil, err
	}

	// HostConnectedEndpointRefs start off with a single reference. We need two.
	e.IncRef()
	return &e, nil
}

// SockType returns the underlying socket type.
func (c *HostConnectedEndpoint) SockType() linux.SockType {
	return c.stype
}

// Send implements ConnectedEndpoint.Send.
func (c *HostConnectedEndpoint) Send(ctx context.Context, data [][]byte, controlMessages ControlMessages, from Address) (int64, bool, *syserr.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !controlMessages.Empty() {
		return 0, false, syserr.ErrInvalidEndpointState
	}

	// Since stream sockets don't preserve message boundaries, we can write
	// only as much of the message as fits in the send buffer.
	truncate := c.stype == linux.SOCK_STREAM

	n, totalLen, err := fdWriteVec(c.fd, data, c.SendMaxQueueSize(), truncate)
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

	// There is no need for the callee to call SendNotify because fdWriteVec
	// uses the host's sendmsg(2) and the host kernel's queue.
	return n, false, syserr.FromError(err)
}

// SendNotify implements ConnectedEndpoint.SendNotify.
func (c *HostConnectedEndpoint) SendNotify() {}

// CloseSend implements ConnectedEndpoint.CloseSend.
func (c *HostConnectedEndpoint) CloseSend() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := unix.Shutdown(c.fd, unix.SHUT_WR); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed write shutdown on host socket %+v: %v", c, err))
	}
}

// CloseNotify implements ConnectedEndpoint.CloseNotify.
func (c *HostConnectedEndpoint) CloseNotify() {}

// Writable implements ConnectedEndpoint.Writable.
func (c *HostConnectedEndpoint) Writable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.fd), waiter.WritableEvents)&waiter.WritableEvents != 0
}

// Passcred implements ConnectedEndpoint.Passcred.
func (c *HostConnectedEndpoint) Passcred() bool {
	// We don't support credential passing for host sockets.
	return false
}

// GetLocalAddress implements ConnectedEndpoint.GetLocalAddress.
func (c *HostConnectedEndpoint) GetLocalAddress() (Address, tcpip.Error) {
	return Address{Addr: c.addr}, nil
}

// EventUpdate implements ConnectedEndpoint.EventUpdate.
func (c *HostConnectedEndpoint) EventUpdate() error {
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
func (c *HostConnectedEndpoint) Recv(ctx context.Context, data [][]byte, creds bool, numRights int, peek bool) (int64, int64, ControlMessages, bool, Address, bool, *syserr.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var cm unet.ControlMessage
	if numRights > 0 {
		cm.EnableFDs(int(numRights))
	}

	// N.B. Unix sockets don't have a receive buffer, the send buffer
	// serves both purposes.
	rl, ml, cl, cTrunc, err := fdReadVec(c.fd, data, []byte(cm), peek, c.RecvMaxQueueSize())
	if rl > 0 && err != nil {
		// We got some data, so all we need to do on error is return
		// the data that we got. Short reads are fine, no need to
		// block.
		err = nil
	}
	if err != nil {
		return 0, 0, ControlMessages{}, false, Address{}, false, syserr.FromError(err)
	}

	// There is no need for the callee to call RecvNotify because fdReadVec uses
	// the host's recvmsg(2) and the host kernel's queue.

	// Trim the control data if we received less than the full amount.
	if cl < uint64(len(cm)) {
		cm = cm[:cl]
	}

	// Avoid extra allocations in the case where there isn't any control data.
	if len(cm) == 0 {
		return rl, ml, ControlMessages{}, cTrunc, Address{Addr: c.addr}, false, nil
	}

	fds, err := cm.ExtractFDs()
	if err != nil {
		return 0, 0, ControlMessages{}, false, Address{}, false, syserr.FromError(err)
	}

	if len(fds) == 0 {
		return rl, ml, ControlMessages{}, cTrunc, Address{Addr: c.addr}, false, nil
	}
	return rl, ml, ControlMessages{Rights: &SCMRights{fds}}, cTrunc, Address{Addr: c.addr}, false, nil
}

// RecvNotify implements Receiver.RecvNotify.
func (c *HostConnectedEndpoint) RecvNotify() {}

// CloseRecv implements Receiver.CloseRecv.
func (c *HostConnectedEndpoint) CloseRecv() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := unix.Shutdown(c.fd, unix.SHUT_RD); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed read shutdown on host socket %+v: %v", c, err))
	}
}

// Readable implements Receiver.Readable.
func (c *HostConnectedEndpoint) Readable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.fd), waiter.ReadableEvents)&waiter.ReadableEvents != 0
}

// SendQueuedSize implements Receiver.SendQueuedSize.
func (c *HostConnectedEndpoint) SendQueuedSize() int64 {
	// TODO(gvisor.dev/issue/273): SendQueuedSize isn't supported for host
	// sockets because we don't allow the sentry to call ioctl(2).
	return -1
}

// RecvQueuedSize implements Receiver.RecvQueuedSize.
func (c *HostConnectedEndpoint) RecvQueuedSize() int64 {
	// TODO(gvisor.dev/issue/273): RecvQueuedSize isn't supported for host
	// sockets because we don't allow the sentry to call ioctl(2).
	return -1
}

// SendMaxQueueSize implements Receiver.SendMaxQueueSize.
func (c *HostConnectedEndpoint) SendMaxQueueSize() int64 {
	return c.sndbuf.Load()
}

// RecvMaxQueueSize implements Receiver.RecvMaxQueueSize.
func (c *HostConnectedEndpoint) RecvMaxQueueSize() int64 {
	// N.B. Unix sockets don't use the receive buffer. We'll claim it is
	// the same size as the send buffer.
	return c.sndbuf.Load()
}

func (c *HostConnectedEndpoint) destroyLocked() {
	c.fd = -1
}

// Release implements ConnectedEndpoint.Release and Receiver.Release.
func (c *HostConnectedEndpoint) Release(ctx context.Context) {
	c.DecRef(func() {
		c.mu.Lock()
		c.destroyLocked()
		c.mu.Unlock()
	})
}

// CloseUnread implements ConnectedEndpoint.CloseUnread.
func (c *HostConnectedEndpoint) CloseUnread() {}

// SetSendBufferSize implements ConnectedEndpoint.SetSendBufferSize.
func (c *HostConnectedEndpoint) SetSendBufferSize(v int64) (newSz int64) {
	// gVisor does not permit setting of SO_SNDBUF for host backed unix
	// domain sockets.
	return c.sndbuf.Load()
}

// SetReceiveBufferSize implements ConnectedEndpoint.SetReceiveBufferSize.
func (c *HostConnectedEndpoint) SetReceiveBufferSize(v int64) (newSz int64) {
	// gVisor does not permit setting of SO_RCVBUF for host backed unix
	// domain sockets. Receive buffer does not have any effect for unix
	// sockets and we claim to be the same as send buffer.
	return c.sndbuf.Load()
}

// SCMConnectedEndpoint represents an endpoint backed by a host fd that was
// passed through a gofer Unix socket. It resembles HostConnectedEndpoint, with the
// following differences:
//   - SCMConnectedEndpoint is not saveable, because the host cannot guarantee
//     the same descriptor number across S/R.
//   - SCMConnectedEndpoint holds ownership of its fd and notification queue.
type SCMConnectedEndpoint struct {
	HostConnectedEndpoint

	queue *waiter.Queue
}

// Init will do the initialization required without holding other locks.
func (e *SCMConnectedEndpoint) Init() error {
	return fdnotifier.AddFD(int32(e.fd), e.queue)
}

// Release implements ConnectedEndpoint.Release and Receiver.Release.
func (e *SCMConnectedEndpoint) Release(ctx context.Context) {
	e.DecRef(func() {
		e.mu.Lock()
		fdnotifier.RemoveFD(int32(e.fd))
		if err := unix.Close(e.fd); err != nil {
			log.Warningf("Failed to close host fd %d: %v", err)
		}
		e.destroyLocked()
		e.mu.Unlock()
	})
}

// NewSCMEndpoint creates a new SCMConnectedEndpoint backed by a host fd that
// was passed through a Unix socket.
//
// The caller is responsible for calling Init(). Additionaly, Release needs to
// be called twice because ConnectedEndpoint is both a Receiver and
// ConnectedEndpoint.
func NewSCMEndpoint(hostFD int, queue *waiter.Queue, addr string) (*SCMConnectedEndpoint, *syserr.Error) {
	e := SCMConnectedEndpoint{
		HostConnectedEndpoint: HostConnectedEndpoint{
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
