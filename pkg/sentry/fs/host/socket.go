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

package host

import (
	"fmt"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	unixsocket "gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

// ConnectedEndpoint is a host FD backed implementation of
// transport.ConnectedEndpoint and transport.Receiver.
//
// +stateify savable
type ConnectedEndpoint struct {
	// ref keeps track of references to a connectedEndpoint.
	ref refs.AtomicRefCount

	queue *waiter.Queue
	path  string

	// If srfd >= 0, it is the host FD that file was imported from.
	srfd int `state:"wait"`

	// stype is the type of Unix socket.
	stype linux.SockType

	// sndbuf is the size of the send buffer.
	//
	// N.B. When this is smaller than the host size, we present it via
	// GetSockOpt and message splitting/rejection in SendMsg, but do not
	// prevent lots of small messages from filling the real send buffer
	// size on the host.
	sndbuf int64 `state:"nosave"`

	// mu protects the fields below.
	mu sync.RWMutex `state:"nosave"`

	// file is an *fd.FD containing the FD backing this endpoint. It must be
	// set to nil if it has been closed.
	file *fd.FD `state:"nosave"`
}

// init performs initialization required for creating new ConnectedEndpoints and
// for restoring them.
func (c *ConnectedEndpoint) init() *syserr.Error {
	family, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return syserr.FromError(err)
	}

	if family != syscall.AF_UNIX {
		// We only allow Unix sockets.
		return syserr.ErrInvalidEndpointState
	}

	stype, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return syserr.FromError(err)
	}

	if err := syscall.SetNonblock(c.file.FD(), true); err != nil {
		return syserr.FromError(err)
	}

	sndbuf, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		return syserr.FromError(err)
	}

	c.stype = linux.SockType(stype)
	c.sndbuf = int64(sndbuf)

	return nil
}

// NewConnectedEndpoint creates a new ConnectedEndpoint backed by a host FD
// that will pretend to be bound at a given sentry path.
//
// The caller is responsible for calling Init(). Additionaly, Release needs to
// be called twice because ConnectedEndpoint is both a transport.Receiver and
// transport.ConnectedEndpoint.
func NewConnectedEndpoint(ctx context.Context, file *fd.FD, queue *waiter.Queue, path string) (*ConnectedEndpoint, *syserr.Error) {
	e := ConnectedEndpoint{
		path:  path,
		queue: queue,
		file:  file,
		srfd:  -1,
	}

	if err := e.init(); err != nil {
		return nil, err
	}

	// AtomicRefCounters start off with a single reference. We need two.
	e.ref.IncRef()

	e.ref.EnableLeakCheck("host.ConnectedEndpoint")

	return &e, nil
}

// Init will do initialization required without holding other locks.
func (c *ConnectedEndpoint) Init() {
	if err := fdnotifier.AddFD(int32(c.file.FD()), c.queue); err != nil {
		panic(err)
	}
}

// NewSocketWithDirent allocates a new unix socket with host endpoint.
//
// This is currently only used by unsaveable Gofer nodes.
//
// NewSocketWithDirent takes ownership of f on success.
func NewSocketWithDirent(ctx context.Context, d *fs.Dirent, f *fd.FD, flags fs.FileFlags) (*fs.File, error) {
	f2 := fd.New(f.FD())
	var q waiter.Queue
	e, err := NewConnectedEndpoint(ctx, f2, &q, "" /* path */)
	if err != nil {
		f2.Release()
		return nil, err.ToError()
	}

	// Take ownship of the FD.
	f.Release()

	e.Init()

	ep := transport.NewExternal(ctx, e.stype, uniqueid.GlobalProviderFromContext(ctx), &q, e, e)

	return unixsocket.NewWithDirent(ctx, d, ep, e.stype, flags), nil
}

// newSocket allocates a new unix socket with host endpoint.
func newSocket(ctx context.Context, orgfd int, saveable bool) (*fs.File, error) {
	ownedfd := orgfd
	srfd := -1
	if saveable {
		var err error
		ownedfd, err = syscall.Dup(orgfd)
		if err != nil {
			return nil, err
		}
		srfd = orgfd
	}
	f := fd.New(ownedfd)
	var q waiter.Queue
	e, err := NewConnectedEndpoint(ctx, f, &q, "" /* path */)
	if err != nil {
		if saveable {
			f.Close()
		} else {
			f.Release()
		}
		return nil, err.ToError()
	}

	e.srfd = srfd
	e.Init()

	ep := transport.NewExternal(ctx, e.stype, uniqueid.GlobalProviderFromContext(ctx), &q, e, e)

	return unixsocket.New(ctx, ep, e.stype), nil
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

	n, totalLen, err := fdWriteVec(c.file.FD(), data, c.SendMaxQueueSize(), truncate)
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

	if err := syscall.Shutdown(c.file.FD(), syscall.SHUT_WR); err != nil {
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

	return fdnotifier.NonBlockingPoll(int32(c.file.FD()), waiter.EventOut)&waiter.EventOut != 0
}

// Passcred implements transport.ConnectedEndpoint.Passcred.
func (c *ConnectedEndpoint) Passcred() bool {
	// We don't support credential passing for host sockets.
	return false
}

// GetLocalAddress implements transport.ConnectedEndpoint.GetLocalAddress.
func (c *ConnectedEndpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{Addr: tcpip.Address(c.path)}, nil
}

// EventUpdate implements transport.ConnectedEndpoint.EventUpdate.
func (c *ConnectedEndpoint) EventUpdate() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.file.FD() != -1 {
		fdnotifier.UpdateFD(int32(c.file.FD()))
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
	rl, ml, cl, cTrunc, err := fdReadVec(c.file.FD(), data, []byte(cm), peek, c.RecvMaxQueueSize())
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
		return rl, ml, transport.ControlMessages{}, cTrunc, tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, nil
	}

	fds, err := cm.ExtractFDs()
	if err != nil {
		return 0, 0, transport.ControlMessages{}, false, tcpip.FullAddress{}, false, syserr.FromError(err)
	}

	if len(fds) == 0 {
		return rl, ml, transport.ControlMessages{}, cTrunc, tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, nil
	}
	return rl, ml, control.New(nil, nil, newSCMRights(fds)), cTrunc, tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, nil
}

// close releases all resources related to the endpoint.
func (c *ConnectedEndpoint) close(context.Context) {
	fdnotifier.RemoveFD(int32(c.file.FD()))
	c.file.Close()
	c.file = nil
}

// RecvNotify implements transport.Receiver.RecvNotify.
func (c *ConnectedEndpoint) RecvNotify() {}

// CloseRecv implements transport.Receiver.CloseRecv.
func (c *ConnectedEndpoint) CloseRecv() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := syscall.Shutdown(c.file.FD(), syscall.SHUT_RD); err != nil {
		// A well-formed UDS shutdown can't fail. See
		// net/unix/af_unix.c:unix_shutdown.
		panic(fmt.Sprintf("failed read shutdown on host socket %+v: %v", c, err))
	}
}

// Readable implements transport.Receiver.Readable.
func (c *ConnectedEndpoint) Readable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fdnotifier.NonBlockingPoll(int32(c.file.FD()), waiter.EventIn)&waiter.EventIn != 0
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

// Release implements transport.ConnectedEndpoint.Release and transport.Receiver.Release.
func (c *ConnectedEndpoint) Release(ctx context.Context) {
	c.ref.DecRefWithDestructor(ctx, c.close)
}

// CloseUnread implements transport.ConnectedEndpoint.CloseUnread.
func (c *ConnectedEndpoint) CloseUnread() {}

// SetSendBufferSize implements transport.ConnectedEndpoint.SetSendBufferSize.
func (c *ConnectedEndpoint) SetSendBufferSize(v int64) (newSz int64) {
	// gVisor does not permit setting of SO_SNDBUF for host backed unix domain
	// sockets.
	return atomic.LoadInt64(&c.sndbuf)
}

// LINT.ThenChange(../../fsimpl/host/socket.go)
