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

// Package unix provides an implementation of the socket.Socket interface for
// the AF_UNIX protocol family.
package unix

import (
	"strings"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/epsocket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// SocketOperations is a Unix socket. It is similar to an epsocket, except it is backed
// by a unix.Endpoint instead of a tcpip.Endpoint.
//
// +stateify savable
type SocketOperations struct {
	refs.AtomicRefCount
	socket.ReceiveTimeout
	fsutil.PipeSeek      `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoFsync       `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoMMap        `state:"nosave"`
	ep                   unix.Endpoint
}

// New creates a new unix socket.
func New(ctx context.Context, endpoint unix.Endpoint) *fs.File {
	dirent := socket.NewDirent(ctx, unixSocketDevice)
	defer dirent.DecRef()
	return NewWithDirent(ctx, dirent, endpoint, fs.FileFlags{Read: true, Write: true})
}

// NewWithDirent creates a new unix socket using an existing dirent.
func NewWithDirent(ctx context.Context, d *fs.Dirent, ep unix.Endpoint, flags fs.FileFlags) *fs.File {
	return fs.NewFile(ctx, d, flags, &SocketOperations{
		ep: ep,
	})
}

// DecRef implements RefCounter.DecRef.
func (s *SocketOperations) DecRef() {
	s.DecRefWithDestructor(func() {
		s.ep.Close()
	})
}

// Release implemements fs.FileOperations.Release.
func (s *SocketOperations) Release() {
	// Release only decrements a reference on s because s may be referenced in
	// the abstract socket namespace.
	s.DecRef()
}

// Endpoint extracts the unix.Endpoint.
func (s *SocketOperations) Endpoint() unix.Endpoint {
	return s.ep
}

// extractPath extracts and validates the address.
func extractPath(sockaddr []byte) (string, *syserr.Error) {
	addr, err := epsocket.GetAddress(linux.AF_UNIX, sockaddr)
	if err != nil {
		return "", err
	}

	// The address is trimmed by GetAddress.
	p := string(addr.Addr)
	if p == "" {
		// Not allowed.
		return "", syserr.ErrInvalidArgument
	}
	if p[len(p)-1] == '/' {
		// Weird, they tried to bind '/a/b/c/'?
		return "", syserr.ErrIsDir
	}

	return p, nil
}

// GetPeerName implements the linux syscall getpeername(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) GetPeerName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr, err := s.ep.GetRemoteAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := epsocket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// GetSockName implements the linux syscall getsockname(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) GetSockName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr, err := s.ep.GetLocalAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := epsocket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// Ioctl implements fs.FileOperations.Ioctl.
func (s *SocketOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return epsocket.Ioctl(ctx, s.ep, io, args)
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) GetSockOpt(t *kernel.Task, level, name, outLen int) (interface{}, *syserr.Error) {
	return epsocket.GetSockOpt(t, s, s.ep, linux.AF_UNIX, s.ep.Type(), level, name, outLen)
}

// Listen implements the linux syscall listen(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return syserr.TranslateNetstackError(s.ep.Listen(backlog))
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *SocketOperations) blockingAccept(t *kernel.Task) (unix.Endpoint, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	// Try to accept the connection; if it fails, then wait until we get a
	// notification.
	for {
		if ep, err := s.ep.Accept(); err != tcpip.ErrWouldBlock {
			return ep, syserr.TranslateNetstackError(err)
		}

		if err := t.Block(ch); err != nil {
			return nil, syserr.FromError(err)
		}
	}
}

// Accept implements the linux syscall accept(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (kdefs.FD, interface{}, uint32, *syserr.Error) {
	// Issue the accept request to get the new endpoint.
	ep, err := s.ep.Accept()
	if err != nil {
		if err != tcpip.ErrWouldBlock || !blocking {
			return 0, nil, 0, syserr.TranslateNetstackError(err)
		}

		var err *syserr.Error
		ep, err = s.blockingAccept(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns := New(t, ep)
	defer ns.DecRef()

	if flags&linux.SOCK_NONBLOCK != 0 {
		flags := ns.Flags()
		flags.NonBlocking = true
		ns.SetFlags(flags.Settable())
	}

	var addr interface{}
	var addrLen uint32
	if peerRequested {
		// Get address of the peer.
		var err *syserr.Error
		addr, addrLen, err = ns.FileOperations.(*SocketOperations).GetPeerName(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	fdFlags := kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	}
	fd, e := t.FDMap().NewFDFrom(0, ns, fdFlags, t.ThreadGroup().Limits())
	if e != nil {
		return 0, nil, 0, syserr.FromError(e)
	}

	return fd, addr, addrLen, nil
}

// Bind implements the linux syscall bind(2) for unix sockets.
func (s *SocketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	p, e := extractPath(sockaddr)
	if e != nil {
		return e
	}

	bep, ok := s.ep.(unix.BoundEndpoint)
	if !ok {
		// This socket can't be bound.
		return syserr.ErrInvalidArgument
	}

	return syserr.TranslateNetstackError(s.ep.Bind(tcpip.FullAddress{Addr: tcpip.Address(p)}, func() *tcpip.Error {
		// Is it abstract?
		if p[0] == 0 {
			if t.IsNetworkNamespaced() {
				return tcpip.ErrInvalidEndpointState
			}
			if err := t.AbstractSockets().Bind(p[1:], bep, s); err != nil {
				// tcpip.ErrPortInUse corresponds to EADDRINUSE.
				return tcpip.ErrPortInUse
			}
		} else {
			// The parent and name.
			var d *fs.Dirent
			var name string

			cwd := t.FSContext().WorkingDirectory()
			defer cwd.DecRef()

			// Is there no slash at all?
			if !strings.Contains(p, "/") {
				d = cwd
				name = p
			} else {
				root := t.FSContext().RootDirectory()
				defer root.DecRef()
				// Find the last path component, we know that something follows
				// that final slash, otherwise extractPath() would have failed.
				lastSlash := strings.LastIndex(p, "/")
				subPath := p[:lastSlash]
				if subPath == "" {
					// Fix up subpath in case file is in root.
					subPath = "/"
				}
				var err error
				d, err = t.MountNamespace().FindInode(t, root, cwd, subPath, fs.DefaultTraversalLimit)
				if err != nil {
					// No path available.
					return tcpip.ErrNoSuchFile
				}
				defer d.DecRef()
				name = p[lastSlash+1:]
			}

			// Create the socket.
			childDir, err := d.Bind(t, t.FSContext().RootDirectory(), name, bep, fs.FilePermissions{User: fs.PermMask{Read: true}})
			if err != nil {
				return tcpip.ErrPortInUse
			}
			childDir.DecRef()
		}

		return nil
	}))
}

// extractEndpoint retrieves the unix.BoundEndpoint associated with a Unix
// socket path. The Release must be called on the unix.BoundEndpoint when the
// caller is done with it.
func extractEndpoint(t *kernel.Task, sockaddr []byte) (unix.BoundEndpoint, *syserr.Error) {
	path, err := extractPath(sockaddr)
	if err != nil {
		return nil, err
	}

	// Is it abstract?
	if path[0] == 0 {
		if t.IsNetworkNamespaced() {
			return nil, syserr.ErrInvalidArgument
		}

		ep := t.AbstractSockets().BoundEndpoint(path[1:])
		if ep == nil {
			// No socket found.
			return nil, syserr.ErrConnectionRefused
		}

		return ep, nil
	}

	// Find the node in the filesystem.
	root := t.FSContext().RootDirectory()
	cwd := t.FSContext().WorkingDirectory()
	d, e := t.MountNamespace().FindInode(t, root, cwd, path, fs.DefaultTraversalLimit)
	cwd.DecRef()
	root.DecRef()
	if e != nil {
		return nil, syserr.FromError(e)
	}

	// Extract the endpoint if one is there.
	ep := d.Inode.BoundEndpoint(path)
	d.DecRef()
	if ep == nil {
		// No socket!
		return nil, syserr.ErrConnectionRefused
	}

	return ep, nil
}

// Connect implements the linux syscall connect(2) for unix sockets.
func (s *SocketOperations) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	ep, err := extractEndpoint(t, sockaddr)
	if err != nil {
		return err
	}
	defer ep.Release()

	// Connect the server endpoint.
	return syserr.TranslateNetstackError(s.ep.Connect(ep))
}

// Writev implements fs.FileOperations.Write.
func (s *SocketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	t := kernel.TaskFromContext(ctx)
	ctrl := control.New(t, s.ep, nil)

	if src.NumBytes() == 0 {
		nInt, tcpipError := s.ep.SendMsg([][]byte{}, ctrl, nil)
		return int64(nInt), syserr.TranslateNetstackError(tcpipError).ToError()
	}

	return src.CopyInTo(ctx, &EndpointWriter{
		Endpoint: s.ep,
		Control:  ctrl,
		To:       nil,
	})
}

// SendMsg implements the linux syscall sendmsg(2) for unix sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	w := EndpointWriter{
		Endpoint: s.ep,
		Control:  controlMessages.Unix,
		To:       nil,
	}
	if len(to) > 0 {
		ep, err := extractEndpoint(t, to)
		if err != nil {
			return 0, err
		}
		defer ep.Release()
		w.To = ep
	}

	if n, err := src.CopyInTo(t, &w); err != syserror.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), syserr.FromError(err)
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	for {
		if n, err := src.CopyInTo(t, &w); err != syserror.ErrWouldBlock {
			return int(n), syserr.FromError(err)
		}

		if err := t.Block(ch); err != nil {
			return 0, syserr.FromError(err)
		}
	}
}

// Passcred implements unix.Credentialer.Passcred.
func (s *SocketOperations) Passcred() bool {
	return s.ep.Passcred()
}

// ConnectedPasscred implements unix.Credentialer.ConnectedPasscred.
func (s *SocketOperations) ConnectedPasscred() bool {
	return s.ep.ConnectedPasscred()
}

// Readiness implements waiter.Waitable.Readiness.
func (s *SocketOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.ep.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *SocketOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.ep.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *SocketOperations) EventUnregister(e *waiter.Entry) {
	s.ep.EventUnregister(e)
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	return epsocket.SetSockOpt(t, s, s.ep, level, name, optVal)
}

// Shutdown implements the linux syscall shutdown(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	f, err := epsocket.ConvertShutdown(how)
	if err != nil {
		return err
	}

	// Issue shutdown request.
	return syserr.TranslateNetstackError(s.ep.Shutdown(f))
}

// Read implements fs.FileOperations.Read.
func (s *SocketOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	return dst.CopyOutFrom(ctx, &EndpointReader{
		Endpoint:  s.ep,
		NumRights: 0,
		Peek:      false,
		From:      nil,
	})
}

// RecvMsg implements the linux syscall recvmsg(2) for sockets backed by
// a unix.Endpoint.
func (s *SocketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, senderAddr interface{}, senderAddrLen uint32, controlMessages socket.ControlMessages, err *syserr.Error) {
	trunc := flags&linux.MSG_TRUNC != 0
	peek := flags&linux.MSG_PEEK != 0

	// Calculate the number of FDs for which we have space and if we are
	// requesting credentials.
	var wantCreds bool
	rightsLen := int(controlDataLen) - syscall.SizeofCmsghdr
	if s.Passcred() {
		// Credentials take priority if they are enabled and there is space.
		wantCreds = rightsLen > 0
		credLen := syscall.CmsgSpace(syscall.SizeofUcred)
		rightsLen -= credLen
	}
	// FDs are 32 bit (4 byte) ints.
	numRights := rightsLen / 4
	if numRights < 0 {
		numRights = 0
	}

	r := EndpointReader{
		Endpoint:  s.ep,
		Creds:     wantCreds,
		NumRights: uintptr(numRights),
		Peek:      peek,
	}
	if senderRequested {
		r.From = &tcpip.FullAddress{}
	}
	if n, err := dst.CopyOutFrom(t, &r); err != syserror.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		var from interface{}
		var fromLen uint32
		if r.From != nil {
			from, fromLen = epsocket.ConvertAddress(linux.AF_UNIX, *r.From)
		}
		if trunc {
			n = int64(r.MsgSize)
		}
		return int(n), from, fromLen, socket.ControlMessages{Unix: r.Control}, syserr.FromError(err)
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		if n, err := dst.CopyOutFrom(t, &r); err != syserror.ErrWouldBlock {
			var from interface{}
			var fromLen uint32
			if r.From != nil {
				from, fromLen = epsocket.ConvertAddress(linux.AF_UNIX, *r.From)
			}
			if trunc {
				n = int64(r.MsgSize)
			}
			return int(n), from, fromLen, socket.ControlMessages{Unix: r.Control}, syserr.FromError(err)
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

// provider is a unix domain socket provider.
type provider struct{}

// Socket returns a new unix domain socket.
func (*provider) Socket(t *kernel.Task, stype unix.SockType, protocol int) (*fs.File, *syserr.Error) {
	// Check arguments.
	if protocol != 0 {
		return nil, syserr.ErrInvalidArgument
	}

	// Create the endpoint and socket.
	var ep unix.Endpoint
	switch stype {
	case linux.SOCK_DGRAM:
		ep = unix.NewConnectionless()
	case linux.SOCK_STREAM, linux.SOCK_SEQPACKET:
		ep = unix.NewConnectioned(stype, t.Kernel())
	default:
		return nil, syserr.ErrInvalidArgument
	}

	return New(t, ep), nil
}

// Pair creates a new pair of AF_UNIX connected sockets.
func (*provider) Pair(t *kernel.Task, stype unix.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	// Check arguments.
	if protocol != 0 {
		return nil, nil, syserr.ErrInvalidArgument
	}

	switch stype {
	case linux.SOCK_STREAM, linux.SOCK_DGRAM, linux.SOCK_SEQPACKET:
	default:
		return nil, nil, syserr.ErrInvalidArgument
	}

	// Create the endpoints and sockets.
	ep1, ep2 := unix.NewPair(stype, t.Kernel())
	s1 := New(t, ep1)
	s2 := New(t, ep2)

	return s1, s2, nil
}

func init() {
	socket.RegisterProvider(linux.AF_UNIX, &provider{})
}
