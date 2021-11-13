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

package unix

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
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

// SocketVFS2 implements socket.SocketVFS2 (and by extension,
// vfs.FileDescriptionImpl) for Unix sockets.
//
// +stateify savable
type SocketVFS2 struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD

	socketVFS2Refs
	socketOpsCommon
}

var _ = socket.SocketVFS2(&SocketVFS2{})

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

	sock := &SocketVFS2{
		socketOpsCommon: socketOpsCommon{
			ep:    ep,
			stype: stype,
		},
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
func (s *SocketVFS2) DecRef(ctx context.Context) {
	s.socketVFS2Refs.DecRef(func() {
		kernel.KernelFromContext(ctx).DeleteSocketVFS2(&s.vfsfd)
		s.ep.Close(ctx)
		if s.abstractNamespace != nil {
			s.abstractNamespace.Remove(s.abstractName, s)
		}
	})
}

// Release implements vfs.FileDescriptionImpl.Release.
func (s *SocketVFS2) Release(ctx context.Context) {
	// Release only decrements a reference on s because s may be referenced in
	// the abstract socket namespace.
	s.DecRef(ctx)
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketVFS2) GetSockOpt(t *kernel.Task, level, name int, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	return netstack.GetSockOpt(t, s, s.ep, linux.AF_UNIX, s.ep.Type(), level, name, outPtr, outLen)
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *SocketVFS2) blockingAccept(t *kernel.Task, peerAddr *tcpip.FullAddress) (transport.Endpoint, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	s.socketOpsCommon.EventRegister(&e)
	defer s.socketOpsCommon.EventUnregister(&e)

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
func (s *SocketVFS2) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
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

	fd, e := t.NewFDFromVFS2(0, ns, kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	})
	if e != nil {
		return 0, nil, 0, syserr.FromError(e)
	}

	t.Kernel().RecordSocketVFS2(ns)
	return fd, addr, addrLen, nil
}

// Bind implements the linux syscall bind(2) for unix sockets.
func (s *SocketVFS2) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
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
				return tcpip.SyserrInvalidEndpointState
			}
			asn := t.AbstractSockets()
			name := p[1:]
			if err := asn.Bind(t, name, bep, s); err != nil {
				// tcpip.SyserrPortInUse corresponds to EADDRINUSE.
				return tcpip.SyserrPortInUse
			}
			s.abstractName = name
			s.abstractNamespace = asn
		} else {
			path := fspath.Parse(p)
			root := t.FSContext().RootDirectoryVFS2()
			defer root.DecRef(t)
			start := root
			relPath := !path.Absolute
			if relPath {
				start = t.FSContext().WorkingDirectoryVFS2()
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
				// File permissions correspond to net/unix/af_unix.c:unix_bind.
				Mode:     linux.FileMode(linux.S_IFSOCK | uint(stat.Mode)&^t.FSContext().Umask()),
				Endpoint: bep,
			})
			if linuxerr.Equals(linuxerr.EEXIST, err) {
				return syserr.ErrAddressInUse
			}
			return syserr.FromError(err)
		}

		return nil
	})
}

// Ioctl implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return netstack.Ioctl(ctx, s.ep, uio, args)
}

// PRead implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Read implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
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
	// Drop control messages.
	r.Control.Release(ctx)
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

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

// Readiness implements waiter.Waitable.Readiness.
func (s *SocketVFS2) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.socketOpsCommon.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *SocketVFS2) EventRegister(e *waiter.Entry) {
	s.socketOpsCommon.EventRegister(e)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *SocketVFS2) EventUnregister(e *waiter.Entry) {
	s.socketOpsCommon.EventUnregister(e)
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// a transport.Endpoint.
func (s *SocketVFS2) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	return netstack.SetSockOpt(t, s, s.ep, level, name, optVal)
}

// providerVFS2 is a unix domain socket provider for VFS2.
type providerVFS2 struct{}

func (*providerVFS2) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
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
func (*providerVFS2) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
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
