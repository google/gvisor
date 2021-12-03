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

package netstack

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SocketVFS2 encapsulates all the state needed to represent a network stack
// endpoint in the kernel context.
//
// +stateify savable
type SocketVFS2 struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD
	vfs.SpliceInFD

	socketOpsCommon
}

var _ = socket.SocketVFS2(&SocketVFS2{})

// NewVFS2 creates a new endpoint socket.
func NewVFS2(t *kernel.Task, family int, skType linux.SockType, protocol int, queue *waiter.Queue, endpoint tcpip.Endpoint) (*vfs.FileDescription, *syserr.Error) {
	if skType == linux.SOCK_STREAM {
		endpoint.SocketOptions().SetDelayOption(true)
	}

	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t, mnt)
	defer d.DecRef(t)

	s := &SocketVFS2{
		socketOpsCommon: socketOpsCommon{
			Queue:    queue,
			family:   family,
			Endpoint: endpoint,
			skType:   skType,
			protocol: protocol,
		},
	}
	s.LockFD.Init(&vfs.FileLocks{})
	vfsfd := &s.vfsfd
	if err := vfsfd.Init(s, linux.O_RDWR, mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, syserr.FromError(err)
	}
	return vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (s *SocketVFS2) Release(ctx context.Context) {
	kernel.KernelFromContext(ctx).DeleteSocketVFS2(&s.vfsfd)
	s.socketOpsCommon.Release(ctx)
}

// Readiness implements waiter.Waitable.Readiness.
func (s *SocketVFS2) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.socketOpsCommon.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *SocketVFS2) EventRegister(e *waiter.Entry) error {
	s.socketOpsCommon.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *SocketVFS2) EventUnregister(e *waiter.Entry) {
	s.socketOpsCommon.EventUnregister(e)
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
	n, _, _, _, _, err := s.nonBlockingRead(ctx, dst, false, false, false)
	if err == syserr.ErrWouldBlock {
		return int64(n), linuxerr.ErrWouldBlock
	}
	if err != nil {
		return 0, err.ToError()
	}
	return int64(n), nil
}

// Write implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	r := src.Reader(ctx)
	n, err := s.Endpoint.Write(r, tcpip.WriteOptions{})
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		return 0, linuxerr.ErrWouldBlock
	}
	if err != nil {
		return 0, syserr.TranslateNetstackError(err).ToError()
	}

	if n < src.NumBytes() {
		return n, linuxerr.ErrWouldBlock
	}

	return n, nil
}

// Accept implements the linux syscall accept(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketVFS2) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	// Issue the accept request to get the new endpoint.
	var peerAddr *tcpip.FullAddress
	if peerRequested {
		peerAddr = &tcpip.FullAddress{}
	}
	ep, wq, terr := s.Endpoint.Accept(peerAddr)
	if terr != nil {
		if _, ok := terr.(*tcpip.ErrWouldBlock); !ok || !blocking {
			return 0, nil, 0, syserr.TranslateNetstackError(terr)
		}

		var err *syserr.Error
		ep, wq, err = s.blockingAccept(t, peerAddr)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns, err := NewVFS2(t, s.family, s.skType, s.protocol, wq, ep)
	if err != nil {
		return 0, nil, 0, err
	}
	defer ns.DecRef(t)

	if err := ns.SetStatusFlags(t, t.Credentials(), uint32(flags&linux.SOCK_NONBLOCK)); err != nil {
		return 0, nil, 0, syserr.FromError(err)
	}

	var addr linux.SockAddr
	var addrLen uint32
	if peerAddr != nil {
		// Get address of the peer and write it to peer slice.
		addr, addrLen = socket.ConvertAddress(s.family, *peerAddr)
	}

	fd, e := t.NewFDFromVFS2(0, ns, kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	})

	t.Kernel().RecordSocketVFS2(ns)

	return fd, addr, addrLen, syserr.FromError(e)
}

// Ioctl implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return s.socketOpsCommon.ioctl(ctx, uio, args)
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketVFS2) GetSockOpt(t *kernel.Task, level, name int, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	// TODO(b/78348848): Unlike other socket options, SO_TIMESTAMP is
	// implemented specifically for netstack.SocketVFS2 rather than
	// commonEndpoint. commonEndpoint should be extended to support socket
	// options where the implementation is not shared, as unix sockets need
	// their own support for SO_TIMESTAMP.
	if level == linux.SOL_SOCKET && name == linux.SO_TIMESTAMP {
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}
		val := primitive.Int32(0)
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.sockOptTimestamp {
			val = 1
		}
		return &val, nil
	}
	if level == linux.SOL_TCP && name == linux.TCP_INQ {
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}
		val := primitive.Int32(0)
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.sockOptInq {
			val = 1
		}
		return &val, nil
	}

	return GetSockOpt(t, s, s.Endpoint, s.family, s.skType, level, name, outPtr, outLen)
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketVFS2) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	// TODO(b/78348848): Unlike other socket options, SO_TIMESTAMP is
	// implemented specifically for netstack.SocketVFS2 rather than
	// commonEndpoint. commonEndpoint should be extended to support socket
	// options where the implementation is not shared, as unix sockets need
	// their own support for SO_TIMESTAMP.
	if level == linux.SOL_SOCKET && name == linux.SO_TIMESTAMP {
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		s.readMu.Lock()
		defer s.readMu.Unlock()
		s.sockOptTimestamp = hostarch.ByteOrder.Uint32(optVal) != 0
		return nil
	}
	if level == linux.SOL_TCP && name == linux.TCP_INQ {
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		s.readMu.Lock()
		defer s.readMu.Unlock()
		s.sockOptInq = hostarch.ByteOrder.Uint32(optVal) != 0
		return nil
	}

	return SetSockOpt(t, s, s.Endpoint, level, name, optVal)
}
