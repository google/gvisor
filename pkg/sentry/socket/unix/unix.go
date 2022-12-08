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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Socket implements socket.Socket (and by extension,
// vfs.FileDescriptionImpl) for Unix sockets.
//
// +stateify savable
type Socket struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD
	socket.SendReceiveTimeout
	socketRefs

	ep    transport.Endpoint
	stype linux.SockType

	// abstractName and abstractNamespace indicate the name and namespace of the
	// socket if it is bound to an abstract socket namespace. Once the socket is
	// bound, they cannot be modified.
	abstractName      string
	abstractNamespace *kernel.AbstractSocketNamespace
}

var _ = socket.Socket(&Socket{})

// NewSockfsFile creates a new socket file in the global sockfs mount and
// returns a corresponding file description.
func NewSockfsFile(t *kernel.Task, ep transport.Endpoint, stype linux.SockType) (*vfs.FileDescription, *syserr.Error) {
	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t, mnt)
	defer d.DecRef(t)

	fd, err := NewFileDescription(ep, stype, linux.O_RDWR, mnt, d, &vfs.FileLocks{})
	if err != nil {
		return nil, syserr.FromError(err)
	}
	return fd, nil
}

// NewFileDescription creates and returns a socket file description
// corresponding to the given mount and dentry.
func NewFileDescription(ep transport.Endpoint, stype linux.SockType, flags uint32, mnt *vfs.Mount, d *vfs.Dentry, locks *vfs.FileLocks) (*vfs.FileDescription, error) {
	// You can create AF_UNIX, SOCK_RAW sockets. They're the same as
	// SOCK_DGRAM and don't require CAP_NET_RAW.
	if stype == linux.SOCK_RAW {
		stype = linux.SOCK_DGRAM
	}

	sock := &Socket{
		ep:    ep,
		stype: stype,
	}
	sock.InitRefs()
	sock.LockFD.Init(locks)
	vfsfd := &sock.vfsfd
	if err := vfsfd.Init(sock, flags, mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return vfsfd, nil
}

// DecRef implements RefCounter.DecRef.
func (s *Socket) DecRef(ctx context.Context) {
	s.socketRefs.DecRef(func() {
		kernel.KernelFromContext(ctx).DeleteSocket(&s.vfsfd)
		s.ep.Close(ctx)
		if s.abstractNamespace != nil {
			s.abstractNamespace.Remove(s.abstractName, s)
		}
	})
}

// Release implements vfs.FileDescriptionImpl.Release.
func (s *Socket) Release(ctx context.Context) {
	// Release only decrements a reference on s because s may be referenced in
	// the abstract socket namespace.
	s.DecRef(ctx)
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) GetSockOpt(t *kernel.Task, level, name int, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	return netstack.GetSockOpt(t, s, s.ep, linux.AF_UNIX, s.ep.Type(), level, name, outPtr, outLen)
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *Socket) blockingAccept(t *kernel.Task, peerAddr *tcpip.FullAddress) (transport.Endpoint, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	s.EventRegister(&e)
	defer s.EventUnregister(&e)

	// Try to accept the connection; if it fails, then wait until we get a
	// notification.
	for {
		if ep, err := s.ep.Accept(t, peerAddr); err != syserr.ErrWouldBlock {
			return ep, err
		}

		if err := t.Block(ch); err != nil {
			return nil, syserr.FromError(err)
		}
	}
}

// Accept implements the linux syscall accept(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	var peerAddr *tcpip.FullAddress
	if peerRequested {
		peerAddr = &tcpip.FullAddress{}
	}
	ep, err := s.ep.Accept(t, peerAddr)
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

	ns, err := NewSockfsFile(t, ep, s.stype)
	if err != nil {
		return 0, nil, 0, err
	}
	defer ns.DecRef(t)

	if flags&linux.SOCK_NONBLOCK != 0 {
		ns.SetStatusFlags(t, t.Credentials(), linux.SOCK_NONBLOCK)
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
func (s *Socket) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	p, e := extractPath(sockaddr)
	if e != nil {
		return e
	}

	bep, ok := s.ep.(transport.BoundEndpoint)
	if !ok {
		// This socket can't be bound.
		return syserr.ErrInvalidArgument
	}

	if p[0] == 0 {
		// Abstract socket. See net/unix/af_unix.c:unix_bind_abstract().
		if t.IsNetworkNamespaced() {
			return syserr.ErrInvalidEndpointState
		}
		asn := t.AbstractSockets()
		name := p[1:]
		if err := asn.Bind(t, name, bep, s); err != nil {
			// syserr.ErrPortInUse corresponds to EADDRINUSE.
			return syserr.ErrPortInUse
		}
		if err := s.ep.Bind(tcpip.FullAddress{Addr: tcpip.Address(p)}); err != nil {
			asn.Remove(name, s)
			return err
		}
		// The socket has been successfully bound. We can update the following.
		s.abstractName = name
		s.abstractNamespace = asn
		return nil
	}

	// See net/unix/af_unix.c:unix_bind_bsd().
	path := fspath.Parse(p)
	root := t.FSContext().RootDirectory()
	defer root.DecRef(t)
	start := root
	relPath := !path.Absolute
	if relPath {
		start = t.FSContext().WorkingDirectory()
		defer start.DecRef(t)
	}
	pop := vfs.PathOperation{
		Root:  root,
		Start: start,
		Path:  path,
	}
	stat, err := s.vfsfd.Stat(t, vfs.StatOptions{Mask: linux.STATX_MODE})
	if err != nil {
		return syserr.FromError(err)
	}
	err = t.Kernel().VFS().MknodAt(t, t.Credentials(), &pop, &vfs.MknodOptions{
		Mode:     linux.FileMode(linux.S_IFSOCK | uint(stat.Mode)&^t.FSContext().Umask()),
		Endpoint: bep,
	})
	if linuxerr.Equals(linuxerr.EEXIST, err) {
		return syserr.ErrAddressInUse
	}
	if err != nil {
		return syserr.FromError(err)
	}
	if err := s.ep.Bind(tcpip.FullAddress{Addr: tcpip.Address(p)}); err != nil {
		if unlinkErr := t.Kernel().VFS().UnlinkAt(t, t.Credentials(), &pop); unlinkErr != nil {
			log.Warningf("failed to unlink socket file created for bind(%q): %v", p, unlinkErr)
		}
		return err
	}
	return nil
}

// Ioctl implements vfs.FileDescriptionImpl.
func (s *Socket) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return netstack.Ioctl(ctx, s.ep, uio, args)
}

// PRead implements vfs.FileDescriptionImpl.
func (s *Socket) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Read implements vfs.FileDescriptionImpl.
func (s *Socket) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

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
	if r.Notify != nil {
		r.Notify()
	}
	// Drop control messages.
	r.Control.Release(ctx)
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.
func (s *Socket) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.
func (s *Socket) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	t := kernel.TaskFromContext(ctx)
	ctrl := control.New(t, s.ep)

	if src.NumBytes() == 0 {
		nInt, notify, err := s.ep.SendMsg(ctx, [][]byte{}, ctrl, nil)
		if notify != nil {
			notify()
		}
		return int64(nInt), err.ToError()
	}

	w := &EndpointWriter{
		Ctx:      ctx,
		Endpoint: s.ep,
		Control:  ctrl,
		To:       nil,
	}

	n, err := src.CopyInTo(ctx, w)
	if w.Notify != nil {
		w.Notify()
	}
	return n, err

}

// Epollable implements FileDescriptionImpl.Epollable.
func (s *Socket) Epollable() bool {
	return true
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	return netstack.SetSockOpt(t, s, s.ep, level, name, optVal)
}

// provider is a unix domain socket provider.
type provider struct{}

func (*provider) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
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

	f, err := NewSockfsFile(t, ep, stype)
	if err != nil {
		ep.Close(t)
		return nil, err
	}
	return f, nil
}

// Pair creates a new pair of AF_UNIX connected sockets.
func (*provider) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
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
	s1, err := NewSockfsFile(t, ep1, stype)
	if err != nil {
		ep1.Close(t)
		ep2.Close(t)
		return nil, nil, err
	}
	s2, err := NewSockfsFile(t, ep2, stype)
	if err != nil {
		s1.DecRef(t)
		ep2.Close(t)
		return nil, nil, err
	}

	return s1, s2, nil
}

func (s *Socket) isPacket() bool {
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
func (s *Socket) Endpoint() transport.Endpoint {
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
func (s *Socket) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr, err := s.ep.GetRemoteAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := socket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// GetSockName implements the linux syscall getsockname(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr, err := s.ep.GetLocalAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := socket.ConvertAddress(linux.AF_UNIX, addr)
	return a, l, nil
}

// Listen implements the linux syscall listen(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return s.ep.Listen(t, backlog)
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

	p := fspath.Parse(path)
	root := t.FSContext().RootDirectory()
	start := root
	relPath := !p.Absolute
	if relPath {
		start = t.FSContext().WorkingDirectory()
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

// Connect implements the linux syscall connect(2) for unix sockets.
func (s *Socket) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
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

// SendMsg implements the linux syscall sendmsg(2) for unix sockets backed by
// a transport.Endpoint.
func (s *Socket) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
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
	if w.Notify != nil {
		w.Notify()
	}
	if err != linuxerr.ErrWouldBlock || flags&linux.MSG_DONTWAIT != 0 {
		return int(n), syserr.FromError(err)
	}

	// Only send SCM Rights once (see net/unix/af_unix.c:unix_stream_sendmsg).
	w.Control.Rights = nil

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	s.EventRegister(&e)
	defer s.EventUnregister(&e)

	total := n
	for {
		// Shorten src to reflect bytes previously written.
		src = src.DropFirst64(n)

		n, err = src.CopyInTo(t, &w)
		if w.Notify != nil {
			w.Notify()
		}
		total += n
		if err != linuxerr.ErrWouldBlock {
			break
		}

		if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				err = linuxerr.ErrWouldBlock
			}
			break
		}
	}

	return int(total), syserr.FromError(err)
}

// Passcred implements transport.Credentialer.Passcred.
func (s *Socket) Passcred() bool {
	return s.ep.Passcred()
}

// ConnectedPasscred implements transport.Credentialer.ConnectedPasscred.
func (s *Socket) ConnectedPasscred() bool {
	return s.ep.ConnectedPasscred()
}

// Readiness implements waiter.Waitable.Readiness.
func (s *Socket) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.ep.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *Socket) EventRegister(e *waiter.Entry) error {
	return s.ep.EventRegister(e)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *Socket) EventUnregister(e *waiter.Entry) {
	s.ep.EventUnregister(e)
}

// Shutdown implements the linux syscall shutdown(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) Shutdown(t *kernel.Task, how int) *syserr.Error {
	f, err := netstack.ConvertShutdown(how)
	if err != nil {
		return err
	}

	// Issue shutdown request.
	return s.ep.Shutdown(f)
}

// RecvMsg implements the linux syscall recvmsg(2) for sockets backed by
// a transport.Endpoint.
func (s *Socket) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, msgFlags int, senderAddr linux.SockAddr, senderAddrLen uint32, controlMessages socket.ControlMessages, err *syserr.Error) {
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
		n, err := dst.CopyOutFrom(t, &r)
		if r.Notify != nil {
			r.Notify()
		}
		return n, err
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
	if n, err := doRead(); err != linuxerr.ErrWouldBlock || dontWait {
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
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	s.EventRegister(&e)
	defer s.EventUnregister(&e)

	for {
		if n, err := doRead(); err != linuxerr.ErrWouldBlock {
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
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				return int(total), msgFlags, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return int(total), msgFlags, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

// State implements socket.Socket.State.
func (s *Socket) State() uint32 {
	return s.ep.State()
}

// Type implements socket.Socket.Type.
func (s *Socket) Type() (family int, skType linux.SockType, protocol int) {
	// Unix domain sockets always have a protocol of 0.
	return linux.AF_UNIX, s.stype, 0
}

func init() {
	socket.RegisterProvider(linux.AF_UNIX, &provider{})
}
