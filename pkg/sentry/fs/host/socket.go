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

package host

import (
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/control"
	unixsocket "gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix"
	"gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

// maxSendBufferSize is the maximum host send buffer size allowed for endpoint.
//
// N.B. 8MB is the default maximum on Linux (2 * sysctl_wmem_max).
const maxSendBufferSize = 8 << 20

// ConnectedEndpoint is a host FD backed implementation of
// unix.ConnectedEndpoint and unix.Receiver.
//
// +stateify savable
type ConnectedEndpoint struct {
	queue *waiter.Queue
	path  string

	// ref keeps track of references to a connectedEndpoint.
	ref refs.AtomicRefCount

	// mu protects fd, readClosed and writeClosed.
	mu sync.RWMutex `state:"nosave"`

	// file is an *fd.FD containing the FD backing this endpoint. It must be
	// set to nil if it has been closed.
	file *fd.FD `state:"nosave"`

	// readClosed is true if the FD has read shutdown or if it has been closed.
	readClosed bool

	// writeClosed is true if the FD has write shutdown or if it has been
	// closed.
	writeClosed bool

	// If srfd >= 0, it is the host FD that file was imported from.
	srfd int `state:"wait"`

	// stype is the type of Unix socket.
	stype unix.SockType

	// sndbuf is the size of the send buffer.
	//
	// N.B. When this is smaller than the host size, we present it via
	// GetSockOpt and message splitting/rejection in SendMsg, but do not
	// prevent lots of small messages from filling the real send buffer
	// size on the host.
	sndbuf int `state:"nosave"`
}

// init performs initialization required for creating new ConnectedEndpoints and
// for restoring them.
func (c *ConnectedEndpoint) init() *tcpip.Error {
	family, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return translateError(err)
	}

	if family != syscall.AF_UNIX {
		// We only allow Unix sockets.
		return tcpip.ErrInvalidEndpointState
	}

	stype, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return translateError(err)
	}

	if err := syscall.SetNonblock(c.file.FD(), true); err != nil {
		return translateError(err)
	}

	sndbuf, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		return translateError(err)
	}
	if sndbuf > maxSendBufferSize {
		log.Warningf("Socket send buffer too large: %d", sndbuf)
		return tcpip.ErrInvalidEndpointState
	}

	c.stype = unix.SockType(stype)
	c.sndbuf = sndbuf

	return nil
}

// NewConnectedEndpoint creates a new ConnectedEndpoint backed by a host FD
// that will pretend to be bound at a given sentry path.
//
// The caller is responsible for calling Init(). Additionaly, Release needs to
// be called twice because ConnectedEndpoint is both a unix.Receiver and
// unix.ConnectedEndpoint.
func NewConnectedEndpoint(file *fd.FD, queue *waiter.Queue, path string) (*ConnectedEndpoint, *tcpip.Error) {
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
	e, err := NewConnectedEndpoint(f2, &q, "" /* path */)
	if err != nil {
		f2.Release()
		return nil, syserr.TranslateNetstackError(err).ToError()
	}

	// Take ownship of the FD.
	f.Release()

	e.Init()

	ep := unix.NewExternal(e.stype, uniqueid.GlobalProviderFromContext(ctx), &q, e, e)

	return unixsocket.NewWithDirent(ctx, d, ep, flags), nil
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
	e, err := NewConnectedEndpoint(f, &q, "" /* path */)
	if err != nil {
		if saveable {
			f.Close()
		} else {
			f.Release()
		}
		return nil, syserr.TranslateNetstackError(err).ToError()
	}

	e.srfd = srfd
	e.Init()

	ep := unix.NewExternal(e.stype, uniqueid.GlobalProviderFromContext(ctx), &q, e, e)

	return unixsocket.New(ctx, ep), nil
}

// Send implements unix.ConnectedEndpoint.Send.
func (c *ConnectedEndpoint) Send(data [][]byte, controlMessages unix.ControlMessages, from tcpip.FullAddress) (uintptr, bool, *tcpip.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.writeClosed {
		return 0, false, tcpip.ErrClosedForSend
	}

	if !controlMessages.Empty() {
		return 0, false, tcpip.ErrInvalidEndpointState
	}

	// Since stream sockets don't preserve message boundaries, we can write
	// only as much of the message as fits in the send buffer.
	truncate := c.stype == unix.SockStream

	n, totalLen, err := fdWriteVec(c.file.FD(), data, c.sndbuf, truncate)
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
	return n, false, translateError(err)
}

// SendNotify implements unix.ConnectedEndpoint.SendNotify.
func (c *ConnectedEndpoint) SendNotify() {}

// CloseSend implements unix.ConnectedEndpoint.CloseSend.
func (c *ConnectedEndpoint) CloseSend() {
	c.mu.Lock()
	c.writeClosed = true
	c.mu.Unlock()
}

// CloseNotify implements unix.ConnectedEndpoint.CloseNotify.
func (c *ConnectedEndpoint) CloseNotify() {}

// Writable implements unix.ConnectedEndpoint.Writable.
func (c *ConnectedEndpoint) Writable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.writeClosed {
		return true
	}
	return fdnotifier.NonBlockingPoll(int32(c.file.FD()), waiter.EventOut)&waiter.EventOut != 0
}

// Passcred implements unix.ConnectedEndpoint.Passcred.
func (c *ConnectedEndpoint) Passcred() bool {
	// We don't support credential passing for host sockets.
	return false
}

// GetLocalAddress implements unix.ConnectedEndpoint.GetLocalAddress.
func (c *ConnectedEndpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{Addr: tcpip.Address(c.path)}, nil
}

// EventUpdate implements unix.ConnectedEndpoint.EventUpdate.
func (c *ConnectedEndpoint) EventUpdate() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.file.FD() != -1 {
		fdnotifier.UpdateFD(int32(c.file.FD()))
	}
}

// Recv implements unix.Receiver.Recv.
func (c *ConnectedEndpoint) Recv(data [][]byte, creds bool, numRights uintptr, peek bool) (uintptr, uintptr, unix.ControlMessages, tcpip.FullAddress, bool, *tcpip.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.readClosed {
		return 0, 0, unix.ControlMessages{}, tcpip.FullAddress{}, false, tcpip.ErrClosedForReceive
	}

	var cm unet.ControlMessage
	if numRights > 0 {
		cm.EnableFDs(int(numRights))
	}

	// N.B. Unix sockets don't have a receive buffer, the send buffer
	// serves both purposes.
	rl, ml, cl, err := fdReadVec(c.file.FD(), data, []byte(cm), peek, c.sndbuf)
	if rl > 0 && err != nil {
		// We got some data, so all we need to do on error is return
		// the data that we got. Short reads are fine, no need to
		// block.
		err = nil
	}
	if err != nil {
		return 0, 0, unix.ControlMessages{}, tcpip.FullAddress{}, false, translateError(err)
	}

	// There is no need for the callee to call RecvNotify because fdReadVec uses
	// the host's recvmsg(2) and the host kernel's queue.

	// Trim the control data if we received less than the full amount.
	if cl < uint64(len(cm)) {
		cm = cm[:cl]
	}

	// Avoid extra allocations in the case where there isn't any control data.
	if len(cm) == 0 {
		return rl, ml, unix.ControlMessages{}, tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, nil
	}

	fds, err := cm.ExtractFDs()
	if err != nil {
		return 0, 0, unix.ControlMessages{}, tcpip.FullAddress{}, false, translateError(err)
	}

	if len(fds) == 0 {
		return rl, ml, unix.ControlMessages{}, tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, nil
	}
	return rl, ml, control.New(nil, nil, newSCMRights(fds)), tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, nil
}

// close releases all resources related to the endpoint.
func (c *ConnectedEndpoint) close() {
	fdnotifier.RemoveFD(int32(c.file.FD()))
	c.file.Close()
	c.file = nil
}

// RecvNotify implements unix.Receiver.RecvNotify.
func (c *ConnectedEndpoint) RecvNotify() {}

// CloseRecv implements unix.Receiver.CloseRecv.
func (c *ConnectedEndpoint) CloseRecv() {
	c.mu.Lock()
	c.readClosed = true
	c.mu.Unlock()
}

// Readable implements unix.Receiver.Readable.
func (c *ConnectedEndpoint) Readable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.readClosed {
		return true
	}
	return fdnotifier.NonBlockingPoll(int32(c.file.FD()), waiter.EventIn)&waiter.EventIn != 0
}

// SendQueuedSize implements unix.Receiver.SendQueuedSize.
func (c *ConnectedEndpoint) SendQueuedSize() int64 {
	// SendQueuedSize isn't supported for host sockets because we don't allow the
	// sentry to call ioctl(2).
	return -1
}

// RecvQueuedSize implements unix.Receiver.RecvQueuedSize.
func (c *ConnectedEndpoint) RecvQueuedSize() int64 {
	// RecvQueuedSize isn't supported for host sockets because we don't allow the
	// sentry to call ioctl(2).
	return -1
}

// SendMaxQueueSize implements unix.Receiver.SendMaxQueueSize.
func (c *ConnectedEndpoint) SendMaxQueueSize() int64 {
	return int64(c.sndbuf)
}

// RecvMaxQueueSize implements unix.Receiver.RecvMaxQueueSize.
func (c *ConnectedEndpoint) RecvMaxQueueSize() int64 {
	// N.B. Unix sockets don't use the receive buffer. We'll claim it is
	// the same size as the send buffer.
	return int64(c.sndbuf)
}

// Release implements unix.ConnectedEndpoint.Release and unix.Receiver.Release.
func (c *ConnectedEndpoint) Release() {
	c.ref.DecRefWithDestructor(c.close)
}

func translateError(err error) *tcpip.Error {
	if err == nil {
		return nil
	}
	return rawfile.TranslateErrno(err.(syscall.Errno))
}
