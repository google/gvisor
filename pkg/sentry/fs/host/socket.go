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
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/control"
	unixsocket "gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

// endpoint encapsulates the state needed to represent a host Unix socket.
//
// TODO: Remove/merge with ConnectedEndpoint.
//
// +stateify savable
type endpoint struct {
	queue waiter.Queue `state:"zerovalue"`

	// stype is the type of Unix socket. (Ex: unix.SockStream,
	// unix.SockSeqpacket, unix.SockDgram)
	stype unix.SockType `state:"nosave"`

	// fd is the host fd backing this file.
	fd int `state:"nosave"`

	// If srfd >= 0, it is the host fd that fd was imported from.
	srfd int `state:"wait"`
}

func (e *endpoint) init() error {
	family, err := syscall.GetsockoptInt(e.fd, syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return err
	}

	if family != syscall.AF_UNIX {
		// We only allow Unix sockets.
		return syserror.EINVAL
	}

	stype, err := syscall.GetsockoptInt(e.fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return err
	}

	if err := syscall.SetNonblock(e.fd, true); err != nil {
		return err
	}

	e.stype = unix.SockType(stype)
	return fdnotifier.AddFD(int32(e.fd), &e.queue)
}

// newEndpoint creates a new host endpoint.
func newEndpoint(fd int, srfd int) (*endpoint, error) {
	ep := &endpoint{fd: fd, srfd: srfd}
	if err := ep.init(); err != nil {
		return nil, err
	}
	return ep, nil
}

// newSocket allocates a new unix socket with host endpoint.
func newSocket(ctx context.Context, fd int, saveable bool) (*fs.File, error) {
	ownedfd := fd
	srfd := -1
	if saveable {
		var err error
		ownedfd, err = syscall.Dup(fd)
		if err != nil {
			return nil, err
		}
		srfd = fd
	}
	ep, err := newEndpoint(ownedfd, srfd)
	if err != nil {
		if saveable {
			syscall.Close(ownedfd)
		}
		return nil, err
	}
	return unixsocket.New(ctx, ep), nil
}

// NewSocketWithDirent allocates a new unix socket with host endpoint.
//
// This is currently only used by unsaveable Gofer nodes.
//
// NewSocketWithDirent takes ownership of f on success.
func NewSocketWithDirent(ctx context.Context, d *fs.Dirent, f *fd.FD, flags fs.FileFlags) (*fs.File, error) {
	ep, err := newEndpoint(f.FD(), -1)
	if err != nil {
		return nil, err
	}

	// Take ownship of the FD.
	f.Release()

	return unixsocket.NewWithDirent(ctx, d, ep, flags), nil
}

// Close implements unix.Endpoint.Close.
func (e *endpoint) Close() {
	fdnotifier.RemoveFD(int32(e.fd))
	syscall.Close(e.fd)
	e.fd = -1
}

// EventRegister implements waiter.Waitable.EventRegister.
func (e *endpoint) EventRegister(we *waiter.Entry, mask waiter.EventMask) {
	e.queue.EventRegister(we, mask)
	fdnotifier.UpdateFD(int32(e.fd))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (e *endpoint) EventUnregister(we *waiter.Entry) {
	e.queue.EventUnregister(we)
	fdnotifier.UpdateFD(int32(e.fd))
}

// Readiness implements unix.Endpoint.Readiness.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(int32(e.fd), mask)
}

// Type implements unix.Endpoint.Type.
func (e *endpoint) Type() unix.SockType {
	return e.stype
}

// Connect implements unix.Endpoint.Connect.
func (e *endpoint) Connect(server unix.BoundEndpoint) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Bind implements unix.Endpoint.Bind.
func (e *endpoint) Bind(address tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Listen implements unix.Endpoint.Listen.
func (e *endpoint) Listen(backlog int) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Accept implements unix.Endpoint.Accept.
func (e *endpoint) Accept() (unix.Endpoint, *tcpip.Error) {
	return nil, tcpip.ErrInvalidEndpointState
}

// Shutdown implements unix.Endpoint.Shutdown.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// GetSockOpt implements unix.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		_, err := syscall.GetsockoptInt(e.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		return translateError(err)
	case *tcpip.PasscredOption:
		// We don't support passcred on host sockets.
		*o = 0
		return nil
	case *tcpip.SendBufferSizeOption:
		v, err := syscall.GetsockoptInt(e.fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		*o = tcpip.SendBufferSizeOption(v)
		return translateError(err)
	case *tcpip.ReceiveBufferSizeOption:
		v, err := syscall.GetsockoptInt(e.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		*o = tcpip.ReceiveBufferSizeOption(v)
		return translateError(err)
	case *tcpip.ReuseAddressOption:
		v, err := syscall.GetsockoptInt(e.fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
		*o = tcpip.ReuseAddressOption(v)
		return translateError(err)
	case *tcpip.ReceiveQueueSizeOption:
		return tcpip.ErrQueueSizeNotSupported
	}
	return tcpip.ErrInvalidEndpointState
}

// SetSockOpt implements unix.Endpoint.SetSockOpt.
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	return nil
}

// GetLocalAddress implements unix.Endpoint.GetLocalAddress.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

// GetRemoteAddress implements unix.Endpoint.GetRemoteAddress.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

// Passcred returns whether or not the SO_PASSCRED socket option is
// enabled on this end.
func (e *endpoint) Passcred() bool {
	// We don't support credential passing for host sockets.
	return false
}

// ConnectedPasscred returns whether or not the SO_PASSCRED socket option
// is enabled on the connected end.
func (e *endpoint) ConnectedPasscred() bool {
	// We don't support credential passing for host sockets.
	return false
}

// SendMsg implements unix.Endpoint.SendMsg.
func (e *endpoint) SendMsg(data [][]byte, controlMessages unix.ControlMessages, to unix.BoundEndpoint) (uintptr, *tcpip.Error) {
	if to != nil {
		return 0, tcpip.ErrInvalidEndpointState
	}
	return sendMsg(e.fd, data, controlMessages)
}

func sendMsg(fd int, data [][]byte, controlMessages unix.ControlMessages) (uintptr, *tcpip.Error) {
	if !controlMessages.Empty() {
		return 0, tcpip.ErrInvalidEndpointState
	}
	n, err := fdWriteVec(fd, data)
	return n, translateError(err)
}

// RecvMsg implements unix.Endpoint.RecvMsg.
func (e *endpoint) RecvMsg(data [][]byte, creds bool, numRights uintptr, peek bool, addr *tcpip.FullAddress) (uintptr, uintptr, unix.ControlMessages, *tcpip.Error) {
	return recvMsg(e.fd, data, numRights, peek, addr)
}

func recvMsg(fd int, data [][]byte, numRights uintptr, peek bool, addr *tcpip.FullAddress) (uintptr, uintptr, unix.ControlMessages, *tcpip.Error) {
	var cm unet.ControlMessage
	if numRights > 0 {
		cm.EnableFDs(int(numRights))
	}
	rl, ml, cl, err := fdReadVec(fd, data, []byte(cm), peek)
	if err == syscall.EAGAIN {
		return 0, 0, unix.ControlMessages{}, tcpip.ErrWouldBlock
	}
	if err != nil {
		return 0, 0, unix.ControlMessages{}, translateError(err)
	}

	// Trim the control data if we received less than the full amount.
	if cl < uint64(len(cm)) {
		cm = cm[:cl]
	}

	// Avoid extra allocations in the case where there isn't any control data.
	if len(cm) == 0 {
		return rl, ml, unix.ControlMessages{}, nil
	}

	fds, err := cm.ExtractFDs()
	if err != nil {
		return 0, 0, unix.ControlMessages{}, translateError(err)
	}

	if len(fds) == 0 {
		return rl, ml, unix.ControlMessages{}, nil
	}
	return rl, ml, control.New(nil, nil, newSCMRights(fds)), nil
}

// NewConnectedEndpoint creates a new ConnectedEndpoint backed by a host FD
// that will pretend to be bound at a given sentry path.
//
// The caller is responsible for calling Init(). Additionaly, Release needs to
// be called twice because host.ConnectedEndpoint is both a unix.Receiver and
// unix.ConnectedEndpoint.
func NewConnectedEndpoint(file *fd.FD, queue *waiter.Queue, path string) (*ConnectedEndpoint, *tcpip.Error) {
	family, err := syscall.GetsockoptInt(file.FD(), syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return nil, translateError(err)
	}

	if family != syscall.AF_UNIX {
		// We only allow Unix sockets.
		return nil, tcpip.ErrInvalidEndpointState
	}

	e := &ConnectedEndpoint{path: path, queue: queue, file: file}

	// AtomicRefCounters start off with a single reference. We need two.
	e.ref.IncRef()

	return e, nil
}

// Init will do initialization required without holding other locks.
func (c *ConnectedEndpoint) Init() {
	if err := fdnotifier.AddFD(int32(c.file.FD()), c.queue); err != nil {
		panic(err)
	}
}

// ConnectedEndpoint is a host FD backed implementation of
// unix.ConnectedEndpoint and unix.Receiver.
//
// ConnectedEndpoint does not support save/restore for now.
type ConnectedEndpoint struct {
	queue *waiter.Queue
	path  string

	// ref keeps track of references to a connectedEndpoint.
	ref refs.AtomicRefCount

	// mu protects fd, readClosed and writeClosed.
	mu sync.RWMutex

	// file is an *fd.FD containing the FD backing this endpoint. It must be
	// set to nil if it has been closed.
	file *fd.FD

	// readClosed is true if the FD has read shutdown or if it has been closed.
	readClosed bool

	// writeClosed is true if the FD has write shutdown or if it has been
	// closed.
	writeClosed bool
}

// Send implements unix.ConnectedEndpoint.Send.
func (c *ConnectedEndpoint) Send(data [][]byte, controlMessages unix.ControlMessages, from tcpip.FullAddress) (uintptr, bool, *tcpip.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.writeClosed {
		return 0, false, tcpip.ErrClosedForSend
	}
	n, err := sendMsg(c.file.FD(), data, controlMessages)
	// There is no need for the callee to call SendNotify because sendMsg uses
	// the host's sendmsg(2) and the host kernel's queue.
	return n, false, err
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
	rl, ml, cm, err := recvMsg(c.file.FD(), data, numRights, peek, nil)
	// There is no need for the callee to call RecvNotify because recvMsg uses
	// the host's recvmsg(2) and the host kernel's queue.
	return rl, ml, cm, tcpip.FullAddress{Addr: tcpip.Address(c.path)}, false, err
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
	v, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		return -1
	}
	return int64(v)
}

// RecvMaxQueueSize implements unix.Receiver.RecvMaxQueueSize.
func (c *ConnectedEndpoint) RecvMaxQueueSize() int64 {
	v, err := syscall.GetsockoptInt(c.file.FD(), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return -1
	}
	return int64(v)
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
