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
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SocketOperations is a Unix socket. It is similar to a netstack socket,
// except it is backed by a transport.Endpoint instead of a tcpip.Endpoint.
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

	socketOperationsRefs
	socketOpsCommon
}

// New creates a new unix socket.
func New(ctx context.Context, endpoint transport.Endpoint, stype linux.SockType) *fs.File {
	dirent := socket.NewDirent(ctx, unixSocketDevice)
	defer dirent.DecRef(ctx)
	return NewWithDirent(ctx, dirent, endpoint, stype, fs.FileFlags{Read: true, Write: true, NonSeekable: true})
}

// NewWithDirent creates a new unix socket using an existing dirent.
func NewWithDirent(ctx context.Context, d *fs.Dirent, ep transport.Endpoint, stype linux.SockType, flags fs.FileFlags) *fs.File {
	// You can create AF_UNIX, SOCK_RAW sockets. They're the same as
	// SOCK_DGRAM and don't require CAP_NET_RAW.
	if stype == linux.SOCK_RAW {
		stype = linux.SOCK_DGRAM
	}

	s := SocketOperations{
		socketOpsCommon: socketOpsCommon{
			ep:    ep,
			stype: stype,
		},
	}
	s.InitRefs()
	return fs.NewFile(ctx, d, flags, &s)
}

// DecRef implements RefCounter.DecRef.
func (s *SocketOperations) DecRef(ctx context.Context) {
	s.socketOperationsRefs.DecRef(func() {
		s.ep.Close(ctx)
		if s.abstractNamespace != nil {
			s.abstractNamespace.Remove(s.abstractName, s)
		}
	})
}

// Release implemements fs.FileOperations.Release.
func (s *SocketOperations) Release(ctx context.Context) {
	// Release only decrements a reference on s because s may be referenced in
	// the abstract socket namespace.
	s.DecRef(ctx)
}

// socketOpsCommon contains the socket operations common to VFS1 and VFS2.
//
// +stateify savable
type socketOpsCommon struct {
	socket.SendReceiveTimeout

	ep    transport.Endpoint
	stype linux.SockType

	// abstractName and abstractNamespace indicate the name and namespace of the
	// socket if it is bound to an abstract socket namespace. Once the socket is
	// bound, they cannot be modified.
	abstractName      string
	abstractNamespace *kernel.AbstractSocketNamespace
}

func (s *socketOpsCommon) isPacket() bool {
	switch s.stype {
	case linux.SOCK_DGRAM, linux.SOCK_SEQPACKET:
		return true
	case linux.SOCK_STREAM:
		return false
	default:
		// We shouldn't have allowed any other socket types during creation.
		panic(fmt.Sprintf("Invalid socket type %d", s.stype))
	}
}

// Endpoint extracts the transport.Endpoint.
func (s *socketOpsCommon) Endpoint() transport.Endpoint {
	return s.ep
}

// extractPath extracts and validates the address.
func extractPath(sockaddr []byte) (string, *syserr.Error) {
	addr, family, err := socket.AddressAndFamily(sockaddr)
	if err != nil {
		if err == syserr.ErrAddressFamilyNotSupported {
			err = syserr.ErrInvalidArgument
		}
		return "", err
	}
	if family != linux.AF_UNIX {
		return "", syserr.ErrInvalidArgument
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
func (s *socketOpsCommon) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr, err := s.ep.GetRemoteAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := socket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// GetSockName implements the linux syscall getsockname(2) for sockets backed by
// a transport.Endpoint.
func (s *socketOpsCommon) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr, err := s.ep.GetLocalAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := socket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// Ioctl implements fs.FileOperations.Ioctl.
func (s *SocketOperations) Ioctl(ctx context.Context, _ *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return netstack.Ioctl(ctx, s.ep, io, args)
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) GetSockOpt(t *kernel.Task, level, name int, outPtr usermem.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	return netstack.GetSockOpt(t, s, s.ep, linux.AF_UNIX, s.ep.Type(), level, name, outPtr, outLen)
}

// Listen implements the linux syscall listen(2) for sockets backed by
// a transport.Endpoint.
func (s *socketOpsCommon) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return s.ep.Listen(backlog)
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *SocketOperations) blockingAccept(t *kernel.Task, peerAddr *tcpip.FullAddress) (transport.Endpoint, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	// Try to accept the connection; if it fails, then wait until we get a
	// notification.
	for {
		if ep, err := s.ep.Accept(peerAddr); err != syserr.ErrWouldBlock {
			return ep, err
		}

		if err := t.Block(ch); err != nil {
			return nil, syserr.FromError(err)
		}
	}
}

// Accept implements the linux syscall accept(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	var peerAddr *tcpip.FullAddress
	if peerRequested {
		peerAddr = &tcpip.FullAddress{}
	}
	ep, err := s.ep.Accept(peerAddr)
	if err != nil {
		if err != syserr.ErrWouldBlock || !blocking {
			return 0, nil, 0, err
		}

		var err *syserr.Error
		ep, err = s.blockingAccept(t, peerAddr)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns := New(t, ep, s.stype)
	defer ns.DecRef(t)

	if flags&linux.SOCK_NONBLOCK != 0 {
		flags := ns.Flags()
		flags.NonBlocking = true
		ns.SetFlags(flags.Settable())
	}

	var addr linux.SockAddr
	var addrLen uint32
	if peerAddr != nil {
		addr, addrLen = socket.ConvertAddress(linux.AF_UNIX, *peerAddr)
	}

	fd, e := t.NewFDFrom(0, ns, kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	})
	if e != nil {
		return 0, nil, 0, syserr.FromError(e)
	}

	t.Kernel().RecordSocket(ns)

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
			asn := t.AbstractSockets()
			name := p[1:]
			if err := asn.Bind(t, name, bep, s); err != nil {
				// syserr.ErrPortInUse corresponds to EADDRINUSE.
				return syserr.ErrPortInUse
			}
			s.abstractName = name
			s.abstractNamespace = asn
		} else {
			// The parent and name.
			var d *fs.Dirent
			var name string

			cwd := t.FSContext().WorkingDirectory()
			defer cwd.DecRef(t)

			// Is there no slash at all?
			if !strings.Contains(p, "/") {
				d = cwd
				name = p
			} else {
				root := t.FSContext().RootDirectory()
				defer root.DecRef(t)
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
				defer d.DecRef(t)
				name = p[lastSlash+1:]
			}

			// Create the socket.
			//
			// Note that the file permissions here are not set correctly (see
			// gvisor.dev/issue/2324). There is no convenient way to get permissions
			// on the socket referred to by s, so we will leave this discrepancy
			// unresolved until VFS2 replaces this code.
			childDir, err := d.Bind(t, t.FSContext().RootDirectory(), name, bep, fs.FilePermissions{User: fs.PermMask{Read: true}})
			if err != nil {
				return syserr.ErrPortInUse
			}
			childDir.DecRef(t)
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

	if kernel.VFS2Enabled {
		p := fspath.Parse(path)
		root := t.FSContext().RootDirectoryVFS2()
		start := root
		relPath := !p.Absolute
		if relPath {
			start = t.FSContext().WorkingDirectoryVFS2()
		}
		pop := vfs.PathOperation{
			Root:               root,
			Start:              start,
			Path:               p,
			FollowFinalSymlink: true,
		}
		ep, e := t.Kernel().VFS().BoundEndpointAt(t, t.Credentials(), &pop, &vfs.BoundEndpointOptions{path})
		root.DecRef(t)
		if relPath {
			start.DecRef(t)
		}
		if e != nil {
			return nil, syserr.FromError(e)
		}
		return ep, nil
	}

	// Find the node in the filesystem.
	root := t.FSContext().RootDirectory()
	cwd := t.FSContext().WorkingDirectory()
	remainingTraversals := uint(fs.DefaultTraversalLimit)
	d, e := t.MountNamespace().FindInode(t, root, cwd, path, &remainingTraversals)
	cwd.DecRef(t)
	root.DecRef(t)
	if e != nil {
		return nil, syserr.FromError(e)
	}

	// Extract the endpoint if one is there.
	ep := d.Inode.BoundEndpoint(path)
	d.DecRef(t)
	if ep == nil {
		// No socket!
		return nil, syserr.ErrConnectionRefused
	}
	return ep, nil
}

// Connect implements the linux syscall connect(2) for unix sockets.
func (s *socketOpsCommon) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	ep, err := extractEndpoint(t, sockaddr)
	if err != nil {
		return err
	}
	defer ep.Release(t)

	// Connect the server endpoint.
	err = s.ep.Connect(t, ep)

	if err == syserr.ErrWrongProtocolForSocket {
		// Linux for abstract sockets returns ErrConnectionRefused
		// instead of ErrWrongProtocolForSocket.
		path, _ := extractPath(sockaddr)
		if len(path) > 0 && path[0] == 0 {
			err = syserr.ErrConnectionRefused
		}
	}

	return err
}

// Write implements fs.FileOperations.Write.
func (s *SocketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	t := kernel.TaskFromContext(ctx)
	ctrl := control.New(t, s.ep, nil)

	if src.NumBytes() == 0 {
		nInt, err := s.ep.SendMsg(ctx, [][]byte{}, ctrl, nil)
		return int64(nInt), err.ToError()
	}

	return src.CopyInTo(ctx, &EndpointWriter{
		Ctx:      ctx,
		Endpoint: s.ep,
		Control:  ctrl,
		To:       nil,
	})
}

// SendMsg implements the linux syscall sendmsg(2) for unix sockets backed by
// a transport.Endpoint.
func (s *socketOpsCommon) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	w := EndpointWriter{
		Ctx:      t,
		Endpoint: s.ep,
		Control:  controlMessages.Unix,
		To:       nil,
	}
	if len(to) > 0 {
		switch s.stype {
		case linux.SOCK_SEQPACKET:
			// to is ignored.
		case linux.SOCK_STREAM:
			if s.State() == linux.SS_CONNECTED {
				return 0, syserr.ErrAlreadyConnected
			}
			return 0, syserr.ErrNotSupported
		default:
			ep, err := extractEndpoint(t, to)
			if err != nil {
				return 0, err
			}
			defer ep.Release(t)
			w.To = ep

			if ep.Passcred() && w.Control.Credentials == nil {
				w.Control.Credentials = control.MakeCreds(t)
			}
		}
	}

	n, err := src.CopyInTo(t, &w)
	if err != syserror.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), syserr.FromError(err)
	}

	// Only send SCM Rights once (see net/unix/af_unix.c:unix_stream_sendmsg).
	w.Control.Rights = nil

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
func (s *socketOpsCommon) Passcred() bool {
	return s.ep.Passcred()
}

// ConnectedPasscred implements transport.Credentialer.ConnectedPasscred.
func (s *socketOpsCommon) ConnectedPasscred() bool {
	return s.ep.ConnectedPasscred()
}

// Readiness implements waiter.Waitable.Readiness.
func (s *socketOpsCommon) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.ep.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *socketOpsCommon) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.ep.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *socketOpsCommon) EventUnregister(e *waiter.Entry) {
	s.ep.EventUnregister(e)
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	return netstack.SetSockOpt(t, s, s.ep, level, name, optVal)
}

// Shutdown implements the linux syscall shutdown(2) for sockets backed by
// a transport.Endpoint.
func (s *socketOpsCommon) Shutdown(t *kernel.Task, how int) *syserr.Error {
	f, err := netstack.ConvertShutdown(how)
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
	r := &EndpointReader{
		Ctx:       ctx,
		Endpoint:  s.ep,
		NumRights: 0,
		Peek:      false,
		From:      nil,
	}
	n, err := dst.CopyOutFrom(ctx, r)
	// Drop control messages.
	r.Control.Release(ctx)
	return n, err
}

// RecvMsg implements the linux syscall recvmsg(2) for sockets backed by
// a transport.Endpoint.
func (s *socketOpsCommon) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, msgFlags int, senderAddr linux.SockAddr, senderAddrLen uint32, controlMessages socket.ControlMessages, err *syserr.Error) {
	trunc := flags&linux.MSG_TRUNC != 0
	peek := flags&linux.MSG_PEEK != 0
	dontWait := flags&linux.MSG_DONTWAIT != 0
	waitAll := flags&linux.MSG_WAITALL != 0
	isPacket := s.isPacket()

	// Calculate the number of FDs for which we have space and if we are
	// requesting credentials.
	var wantCreds bool
	rightsLen := int(controlDataLen) - unix.SizeofCmsghdr
	if s.Passcred() {
		// Credentials take priority if they are enabled and there is space.
		wantCreds = rightsLen > 0
		if !wantCreds {
			msgFlags |= linux.MSG_CTRUNC
		}
		credLen := unix.CmsgSpace(unix.SizeofUcred)
		rightsLen -= credLen
	}
	// FDs are 32 bit (4 byte) ints.
	numRights := rightsLen / 4
	if numRights < 0 {
		numRights = 0
	}

	r := EndpointReader{
		Ctx:       t,
		Endpoint:  s.ep,
		Creds:     wantCreds,
		NumRights: numRights,
		Peek:      peek,
	}
	if senderRequested {
		r.From = &tcpip.FullAddress{}
	}

	doRead := func() (int64, error) {
		return dst.CopyOutFrom(t, &r)
	}

	// If MSG_TRUNC is set with a zero byte destination then we still need
	// to read the message and discard it, or in the case where MSG_PEEK is
	// set, leave it be. In both cases the full message length must be
	// returned.
	if trunc && dst.Addrs.NumBytes() == 0 {
		doRead = func() (int64, error) {
			err := r.Truncate()
			// Always return zero for bytes read since the destination size is
			// zero.
			return 0, err
		}

	}

	var total int64
	if n, err := doRead(); err != syserror.ErrWouldBlock || dontWait {
		var from linux.SockAddr
		var fromLen uint32
		if r.From != nil && len([]byte(r.From.Addr)) != 0 {
			from, fromLen = socket.ConvertAddress(linux.AF_UNIX, *r.From)
		}

		if r.ControlTrunc {
			msgFlags |= linux.MSG_CTRUNC
		}

		if err != nil || dontWait || !waitAll || isPacket || n >= dst.NumBytes() {
			if isPacket && n < int64(r.MsgSize) {
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
		if n, err := doRead(); err != syserror.ErrWouldBlock {
			var from linux.SockAddr
			var fromLen uint32
			if r.From != nil {
				from, fromLen = socket.ConvertAddress(linux.AF_UNIX, *r.From)
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

			streamPeerClosed := s.stype == linux.SOCK_STREAM && n == 0 && err == nil
			if err != nil || !waitAll || isPacket || n >= dst.NumBytes() || streamPeerClosed {
				if total > 0 {
					err = nil
				}
				if isPacket && n < int64(r.MsgSize) {
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
func (s *socketOpsCommon) State() uint32 {
	return s.ep.State()
}

// Type implements socket.Socket.Type.
func (s *socketOpsCommon) Type() (family int, skType linux.SockType, protocol int) {
	// Unix domain sockets always have a protocol of 0.
	return linux.AF_UNIX, s.stype, 0
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
	switch stype {
	case linux.SOCK_DGRAM, linux.SOCK_RAW:
		ep = transport.NewConnectionless(t)
	case linux.SOCK_SEQPACKET, linux.SOCK_STREAM:
		ep = transport.NewConnectioned(t, stype, t.Kernel())
	default:
		return nil, syserr.ErrInvalidArgument
	}

	return New(t, ep, stype), nil
}

// Pair creates a new pair of AF_UNIX connected sockets.
func (*provider) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	// Check arguments.
	if protocol != 0 && protocol != linux.AF_UNIX /* PF_UNIX */ {
		return nil, nil, syserr.ErrProtocolNotSupported
	}

	switch stype {
	case linux.SOCK_STREAM, linux.SOCK_DGRAM, linux.SOCK_SEQPACKET, linux.SOCK_RAW:
		// Ok
	default:
		return nil, nil, syserr.ErrInvalidArgument
	}

	// Create the endpoints and sockets.
	ep1, ep2 := transport.NewPair(t, stype, t.Kernel())
	s1 := New(t, ep1, stype)
	s2 := New(t, ep2, stype)

	return s1, s2, nil
}

func init() {
	socket.RegisterProvider(linux.AF_UNIX, &provider{})
	socket.RegisterProviderVFS2(linux.AF_UNIX, &providerVFS2{})
}
