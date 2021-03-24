// Copyright 2020 The gVisor Authors.
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

package host

import (
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Create a new host-backed endpoint from the given fd and its corresponding
// notification queue.
func newEndpoint(ctx context.Context, hostFD int, queue *waiter.Queue) (transport.Endpoint, error) {
	// Set up an external transport.Endpoint using the host fd.
	addr := fmt.Sprintf("hostfd:[%d]", hostFD)
	e, err := NewConnectedEndpoint(ctx, hostFD, addr, true /* saveable */)
	if err != nil {
		return nil, err.ToError()
	}
	ep := transport.NewExternal(ctx, e.stype, uniqueid.GlobalProviderFromContext(ctx), queue, e, e)
	return ep, nil
}

// ConnectedEndpoint is an implementation of transport.ConnectedEndpoint and
// transport.Receiver. It is backed by a host fd that was imported at sentry
// startup. This fd is shared with a hostfs inode, which retains ownership of
// it.
//
// ConnectedEndpoint is saveable, since we expect that the host will provide
// the same fd upon restore.
//
// As of this writing, we only allow Unix sockets to be imported.
//
// +stateify savable
type ConnectedEndpoint struct {
	ConnectedEndpointRefs

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
	sndbuf int64 `state:"nosave"`

	// stype is the type of Unix socket.
	stype linux.SockType
}

// init performs initialization required for creating new ConnectedEndpoints and
// for restoring them.
func (c *ConnectedEndpoint) init() *syserr.Error {
	c.InitRefs()

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
	atomic.StoreInt64(&c.sndbuf, int64(sndbuf))

	return nil
}

// NewConnectedEndpoint creates a new ConnectedEndpoint backed by a host fd
// imported at sentry startup,
//
// The caller is responsible for calling Init(). Additionaly, Release needs to
// be called twice because ConnectedEndpoint is both a transport.Receiver and
// transport.ConnectedEndpoint.
func NewConnectedEndpoint(ctx context.Context, hostFD int, addr string, saveable bool) (*ConnectedEndpoint, *syserr.Error) {
	e := ConnectedEndpoint{
		fd:   hostFD,
		addr: addr,
	}

	if err := e.init(); err != nil {
		return nil, err
	}

	// ConnectedEndpointRefs start off with a single reference. We need two.
	e.IncRef()
	return &e, nil
}

// Send implements transport.ConnectedEndpoint.Send.
func (c *ConnectedEndpoint) Send(ctx context.Context, data [][]byte, controlMessages transport.ControlMessages, from tcpip.FullAddress) (int64, bool, *syserr.Error) {
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
		err = syserror.EAGAIN
	}
	if n > 0 && err != syserror.EAGAIN {
		// The caller may need to block to send more data, but
		// otherwise there isn't anything that can be done about an
		// error with a partial write.
		err = nil
	}

	// There is no need for the callee to call SendNotify because fdWriteVec
	// uses the host's sendmsg(2) and the host kernel's queue.
	return n, false, syserr.FromError(err)
}

// SendNotify implements transport.ConnectedEndpoint.SendNotify.
func (c *ConnectedEndpoint) SendNotify() {}

// CloseSend implements transport.ConnectedEndpoint.CloseSend.
func (c *ConnectedEndpoint) CloseSend() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := unix.Shutdown(c.fd, unix.SHUT_WR); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed write shutdown on host socket %+v: %v", c, err))
	}
}

// CloseNotify implements transport.ConnectedEndpoint.CloseNotify.
func (c *ConnectedEndpoint) CloseNotify() {}

// Writable implements transport.ConnectedEndpoint.Writable.
func (c *ConnectedEndpoint) Writable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.fd), waiter.WritableEvents)&waiter.WritableEvents != 0
}

// Passcred implements transport.ConnectedEndpoint.Passcred.
func (c *ConnectedEndpoint) Passcred() bool {
	// We don't support credential passing for host sockets.
	return false
}

// GetLocalAddress implements transport.ConnectedEndpoint.GetLocalAddress.
func (c *ConnectedEndpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{Addr: tcpip.Address(c.addr)}, nil
}

// EventUpdate implements transport.ConnectedEndpoint.EventUpdate.
func (c *ConnectedEndpoint) EventUpdate() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.fd != -1 {
		fdnotifier.UpdateFD(int32(c.fd))
	}
}

// Recv implements transport.Receiver.Recv.
func (c *ConnectedEndpoint) Recv(ctx context.Context, data [][]byte, creds bool, numRights int, peek bool) (int64, int64, transport.ControlMessages, bool, tcpip.FullAddress, bool, *syserr.Error) {
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
		return 0, 0, transport.ControlMessages{}, false, tcpip.FullAddress{}, false, syserr.FromError(err)
	}

	// There is no need for the callee to call RecvNotify because fdReadVec uses
	// the host's recvmsg(2) and the host kernel's queue.

	// Trim the control data if we received less than the full amount.
	if cl < uint64(len(cm)) {
		cm = cm[:cl]
	}

	// Avoid extra allocations in the case where there isn't any control data.
	if len(cm) == 0 {
		return rl, ml, transport.ControlMessages{}, cTrunc, tcpip.FullAddress{Addr: tcpip.Address(c.addr)}, false, nil
	}

	fds, err := cm.ExtractFDs()
	if err != nil {
		return 0, 0, transport.ControlMessages{}, false, tcpip.FullAddress{}, false, syserr.FromError(err)
	}

	if len(fds) == 0 {
		return rl, ml, transport.ControlMessages{}, cTrunc, tcpip.FullAddress{Addr: tcpip.Address(c.addr)}, false, nil
	}
	return rl, ml, control.NewVFS2(nil, nil, newSCMRights(fds)), cTrunc, tcpip.FullAddress{Addr: tcpip.Address(c.addr)}, false, nil
}

// RecvNotify implements transport.Receiver.RecvNotify.
func (c *ConnectedEndpoint) RecvNotify() {}

// CloseRecv implements transport.Receiver.CloseRecv.
func (c *ConnectedEndpoint) CloseRecv() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := unix.Shutdown(c.fd, unix.SHUT_RD); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed read shutdown on host socket %+v: %v", c, err))
	}
}

// Readable implements transport.Receiver.Readable.
func (c *ConnectedEndpoint) Readable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.fd), waiter.ReadableEvents)&waiter.ReadableEvents != 0
}

// SendQueuedSize implements transport.Receiver.SendQueuedSize.
func (c *ConnectedEndpoint) SendQueuedSize() int64 {
	// TODO(gvisor.dev/issue/273): SendQueuedSize isn't supported for host
	// sockets because we don't allow the sentry to call ioctl(2).
	return -1
}

// RecvQueuedSize implements transport.Receiver.RecvQueuedSize.
func (c *ConnectedEndpoint) RecvQueuedSize() int64 {
	// TODO(gvisor.dev/issue/273): RecvQueuedSize isn't supported for host
	// sockets because we don't allow the sentry to call ioctl(2).
	return -1
}

// SendMaxQueueSize implements transport.Receiver.SendMaxQueueSize.
func (c *ConnectedEndpoint) SendMaxQueueSize() int64 {
	return atomic.LoadInt64(&c.sndbuf)
}

// RecvMaxQueueSize implements transport.Receiver.RecvMaxQueueSize.
func (c *ConnectedEndpoint) RecvMaxQueueSize() int64 {
	// N.B. Unix sockets don't use the receive buffer. We'll claim it is
	// the same size as the send buffer.
	return atomic.LoadInt64(&c.sndbuf)
}

func (c *ConnectedEndpoint) destroyLocked() {
	c.fd = -1
}

// Release implements transport.ConnectedEndpoint.Release and
// transport.Receiver.Release.
func (c *ConnectedEndpoint) Release(ctx context.Context) {
	c.DecRef(func() {
		c.mu.Lock()
		c.destroyLocked()
		c.mu.Unlock()
	})
}

// CloseUnread implements transport.ConnectedEndpoint.CloseUnread.
func (c *ConnectedEndpoint) CloseUnread() {}

// SetSendBufferSize implements transport.ConnectedEndpoint.SetSendBufferSize.
func (c *ConnectedEndpoint) SetSendBufferSize(v int64) (newSz int64) {
	// gVisor does not permit setting of SO_SNDBUF for host backed unix domain
	// sockets.
	return atomic.LoadInt64(&c.sndbuf)
}

// SCMConnectedEndpoint represents an endpoint backed by a host fd that was
// passed through a gofer Unix socket. It resembles ConnectedEndpoint, with the
// following differences:
// - SCMConnectedEndpoint is not saveable, because the host cannot guarantee
// the same descriptor number across S/R.
// - SCMConnectedEndpoint holds ownership of its fd and notification queue.
type SCMConnectedEndpoint struct {
	ConnectedEndpoint

	queue *waiter.Queue
}

// Init will do the initialization required without holding other locks.
func (e *SCMConnectedEndpoint) Init() error {
	return fdnotifier.AddFD(int32(e.fd), e.queue)
}

// Release implements transport.ConnectedEndpoint.Release and
// transport.Receiver.Release.
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
// be called twice because ConnectedEndpoint is both a transport.Receiver and
// transport.ConnectedEndpoint.
func NewSCMEndpoint(ctx context.Context, hostFD int, queue *waiter.Queue, addr string) (*SCMConnectedEndpoint, *syserr.Error) {
	e := SCMConnectedEndpoint{
		ConnectedEndpoint: ConnectedEndpoint{
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
