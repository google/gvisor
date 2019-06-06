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
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// SocketOperations is a Unix socket. It is similar to an epsocket, except it
// is backed by a transport.Endpoint instead of a tcpip.Endpoint.
//
// +stateify savable
type SocketOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	refs.AtomicRefCount
	socket.SendReceiveTimeout

	ep       transport.Endpoint
	isPacket bool
}

// New creates a new unix socket.
func New(ctx context.Context, endpoint transport.Endpoint, isPacket bool) *fs.File {
	dirent := socket.NewDirent(ctx, unixSocketDevice)
	defer dirent.DecRef()
	return NewWithDirent(ctx, dirent, endpoint, isPacket, fs.FileFlags{Read: true, Write: true})
}

// NewWithDirent creates a new unix socket using an existing dirent.
func NewWithDirent(ctx context.Context, d *fs.Dirent, ep transport.Endpoint, isPacket bool, flags fs.FileFlags) *fs.File {
	return fs.NewFile(ctx, d, flags, &SocketOperations{
		ep:       ep,
		isPacket: isPacket,
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

// Endpoint extracts the transport.Endpoint.
func (s *SocketOperations) Endpoint() transport.Endpoint {
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
// a transport.Endpoint.
func (s *SocketOperations) GetPeerName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr, err := s.ep.GetRemoteAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := epsocket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// GetSockName implements the linux syscall getsockname(2) for sockets backed by
// a transport.Endpoint.
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
// a transport.Endpoint.
func (s *SocketOperations) GetSockOpt(t *kernel.Task, level, name, outLen int) (interface{}, *syserr.Error) {
	return epsocket.GetSockOpt(t, s, s.ep, linux.AF_UNIX, s.ep.Type(), level, name, outLen)
}

// Listen implements the linux syscall listen(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return s.ep.Listen(backlog)
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *SocketOperations) blockingAccept(t *kernel.Task) (transport.Endpoint, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	// Try to accept the connection; if it fails, then wait until we get a
	// notification.
	for {
		if ep, err := s.ep.Accept(); err != syserr.ErrWouldBlock {
			return ep, err
		}

		if err := t.Block(ch); err != nil {
			return nil, syserr.FromError(err)
		}
	}
}

// Accept implements the linux syscall accept(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (kdefs.FD, interface{}, uint32, *syserr.Error) {
	// Issue the accept request to get the new endpoint.
	ep, err := s.ep.Accept()
	if err != nil {
		if err != syserr.ErrWouldBlock || !blocking {
			return 0, nil, 0, err
		}

		var err *syserr.Error
		ep, err = s.blockingAccept(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns := New(t, ep, s.isPacket)
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

	t.Kernel().RecordSocket(ns, linux.AF_UNIX)

	return fd, addr, addrLen, nil
}

// Bind implements the linux syscall bind(2) for unix sockets.
func (s *SocketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	p, e := extractPath(sockaddr)
	if e != nil {
		return e
	}

	bep, ok := s.ep.(transport.BoundEndpoint)
	if !ok {
		// This socket can't be bound.
		return syserr.ErrInvalidArgument
	}

	return s.ep.Bind(tcpip.FullAddress{Addr: tcpip.Address(p)}, func() *syserr.Error {
		// Is it abstract?
		if p[0] == 0 {
			if t.IsNetworkNamespaced() {
				return syserr.ErrInvalidEndpointState
			}
			if err := t.AbstractSockets().Bind(p[1:], bep, s); err != nil {
				// syserr.ErrPortInUse corresponds to EADDRINUSE.
				return syserr.ErrPortInUse
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
				remainingTraversals := uint(fs.DefaultTraversalLimit)
				d, err = t.MountNamespace().FindInode(t, root, cwd, subPath, &remainingTraversals)
				if err != nil {
					// No path available.
					return syserr.ErrNoSuchFile
				}
				defer d.DecRef()
				name = p[lastSlash+1:]
			}

			// Create the socket.
			childDir, err := d.Bind(t, t.FSContext().RootDirectory(), name, bep, fs.FilePermissions{User: fs.PermMask{Read: true}})
			if err != nil {
				return syserr.ErrPortInUse
			}
			childDir.DecRef()
		}

		return nil
	})
}

// extractEndpoint retrieves the transport.BoundEndpoint associated with a Unix
// socket path. The Release must be called on the transport.BoundEndpoint when
// the caller is done with it.
func extractEndpoint(t *kernel.Task, sockaddr []byte) (transport.BoundEndpoint, *syserr.Error) {
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
	remainingTraversals := uint(fs.DefaultTraversalLimit)
	d, e := t.MountNamespace().FindInode(t, root, cwd, path, &remainingTraversals)
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
	return s.ep.Connect(ep)
}

// Writev implements fs.FileOperations.Write.
func (s *SocketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	t := kernel.TaskFromContext(ctx)
	ctrl := control.New(t, s.ep, nil)

	if src.NumBytes() == 0 {
		nInt, err := s.ep.SendMsg([][]byte{}, ctrl, nil)
		return int64(nInt), err.ToError()
	}

	return src.CopyInTo(ctx, &EndpointWriter{
		Endpoint: s.ep,
		Control:  ctrl,
		To:       nil,
	})
}

// SendMsg implements the linux syscall sendmsg(2) for unix sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
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

		if ep.Passcred() && w.Control.Credentials == nil {
			w.Control.Credentials = control.MakeCreds(t)
		}
	}

	n, err := src.CopyInTo(t, &w)
	if err != syserror.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), syserr.FromError(err)
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	total := n
	for {
		// Shorten src to reflect bytes previously written.
		src = src.DropFirst64(n)

		n, err = src.CopyInTo(t, &w)
		total += n
		if err != syserror.ErrWouldBlock {
			break
		}

		if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				err = syserror.ErrWouldBlock
			}
			break
		}
	}

	return int(total), syserr.FromError(err)
}

// Passcred implements transport.Credentialer.Passcred.
func (s *SocketOperations) Passcred() bool {
	return s.ep.Passcred()
}

// ConnectedPasscred implements transport.Credentialer.ConnectedPasscred.
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
// a transport.Endpoint.
func (s *SocketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	return epsocket.SetSockOpt(t, s, s.ep, level, name, optVal)
}

// Shutdown implements the linux syscall shutdown(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	f, err := epsocket.ConvertShutdown(how)
	if err != nil {
		return err
	}

	// Issue shutdown request.
	return s.ep.Shutdown(f)
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
// a transport.Endpoint.
func (s *SocketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, msgFlags int, senderAddr interface{}, senderAddrLen uint32, controlMessages socket.ControlMessages, err *syserr.Error) {
	trunc := flags&linux.MSG_TRUNC != 0
	peek := flags&linux.MSG_PEEK != 0
	dontWait := flags&linux.MSG_DONTWAIT != 0
	waitAll := flags&linux.MSG_WAITALL != 0

	// Calculate the number of FDs for which we have space and if we are
	// requesting credentials.
	var wantCreds bool
	rightsLen := int(controlDataLen) - syscall.SizeofCmsghdr
	if s.Passcred() {
		// Credentials take priority if they are enabled and there is space.
		wantCreds = rightsLen > 0
		if !wantCreds {
			msgFlags |= linux.MSG_CTRUNC
		}
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
	var total int64
	if n, err := dst.CopyOutFrom(t, &r); err != syserror.ErrWouldBlock || dontWait {
		var from interface{}
		var fromLen uint32
		if r.From != nil && len([]byte(r.From.Addr)) != 0 {
			from, fromLen = epsocket.ConvertAddress(linux.AF_UNIX, *r.From)
		}

		if r.ControlTrunc {
			msgFlags |= linux.MSG_CTRUNC
		}

		if err != nil || dontWait || !waitAll || s.isPacket || n >= dst.NumBytes() {
			if s.isPacket && n < int64(r.MsgSize) {
				msgFlags |= linux.MSG_TRUNC
			}

			if trunc {
				n = int64(r.MsgSize)
			}

			return int(n), msgFlags, from, fromLen, socket.ControlMessages{Unix: r.Control}, syserr.FromError(err)
		}

		// Don't overwrite any data we received.
		dst = dst.DropFirst64(n)
		total += n
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

			if r.ControlTrunc {
				msgFlags |= linux.MSG_CTRUNC
			}

			if trunc {
				// n and r.MsgSize are the same for streams.
				total += int64(r.MsgSize)
			} else {
				total += n
			}

			if err != nil || !waitAll || s.isPacket || n >= dst.NumBytes() {
				if total > 0 {
					err = nil
				}
				if s.isPacket && n < int64(r.MsgSize) {
					msgFlags |= linux.MSG_TRUNC
				}
				return int(total), msgFlags, from, fromLen, socket.ControlMessages{Unix: r.Control}, syserr.FromError(err)
			}

			// Don't overwrite any data we received.
			dst = dst.DropFirst64(n)
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if total > 0 {
				err = nil
			}
			if err == syserror.ETIMEDOUT {
				return int(total), msgFlags, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return int(total), msgFlags, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

// State implements socket.Socket.State.
func (s *SocketOperations) State() uint32 {
	return s.ep.State()
}

// provider is a unix domain socket provider.
type provider struct{}

// Socket returns a new unix domain socket.
func (*provider) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *syserr.Error) {
	// Check arguments.
	if protocol != 0 && protocol != linux.AF_UNIX /* PF_UNIX */ {
		return nil, syserr.ErrProtocolNotSupported
	}

	// Create the endpoint and socket.
	var ep transport.Endpoint
	var isPacket bool
	switch stype {
	case linux.SOCK_DGRAM:
		isPacket = true
		ep = transport.NewConnectionless()
	case linux.SOCK_SEQPACKET:
		isPacket = true
		fallthrough
	case linux.SOCK_STREAM:
		ep = transport.NewConnectioned(stype, t.Kernel())
	default:
		return nil, syserr.ErrInvalidArgument
	}

	return New(t, ep, isPacket), nil
}

// Pair creates a new pair of AF_UNIX connected sockets.
func (*provider) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	// Check arguments.
	if protocol != 0 && protocol != linux.AF_UNIX /* PF_UNIX */ {
		return nil, nil, syserr.ErrProtocolNotSupported
	}

	var isPacket bool
	switch stype {
	case linux.SOCK_STREAM:
	case linux.SOCK_DGRAM, linux.SOCK_SEQPACKET:
		isPacket = true
	default:
		return nil, nil, syserr.ErrInvalidArgument
	}

	// Create the endpoints and sockets.
	ep1, ep2 := transport.NewPair(stype, t.Kernel())
	s1 := New(t, ep1, isPacket)
	s2 := New(t, ep2, isPacket)

	return s1, s2, nil
}

func init() {
	socket.RegisterProvider(linux.AF_UNIX, &provider{})
}
