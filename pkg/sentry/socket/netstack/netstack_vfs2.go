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
	"gvisor.dev/gvisor/pkg/amutex"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SocketVFS2 encapsulates all the state needed to represent a network stack
// endpoint in the kernel context.
type SocketVFS2 struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD

	socketOpsCommon
}

var _ = socket.SocketVFS2(&SocketVFS2{})

// NewVFS2 creates a new endpoint socket.
func NewVFS2(t *kernel.Task, family int, skType linux.SockType, protocol int, queue *waiter.Queue, endpoint tcpip.Endpoint) (*vfs.FileDescription, *syserr.Error) {
	if skType == linux.SOCK_STREAM {
		if err := endpoint.SetSockOptBool(tcpip.DelayOption, true); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
	}

	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t.Credentials(), mnt)

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

// Readiness implements waiter.Waitable.Readiness.
func (s *SocketVFS2) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.socketOpsCommon.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *SocketVFS2) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.socketOpsCommon.EventRegister(e, mask)
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
		return 0, syserror.EOPNOTSUPP
	}

	if dst.NumBytes() == 0 {
		return 0, nil
	}
	n, _, _, _, _, err := s.nonBlockingRead(ctx, dst, false, false, false)
	if err == syserr.ErrWouldBlock {
		return int64(n), syserror.ErrWouldBlock
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
		return 0, syserror.EOPNOTSUPP
	}

	f := &ioSequencePayload{ctx: ctx, src: src}
	n, resCh, err := s.Endpoint.Write(f, tcpip.WriteOptions{})
	if err == tcpip.ErrWouldBlock {
		return 0, syserror.ErrWouldBlock
	}

	if resCh != nil {
		if err := amutex.Block(ctx, resCh); err != nil {
			return 0, err
		}
		n, _, err = s.Endpoint.Write(f, tcpip.WriteOptions{})
	}

	if err != nil {
		return 0, syserr.TranslateNetstackError(err).ToError()
	}

	if int64(n) < src.NumBytes() {
		return int64(n), syserror.ErrWouldBlock
	}

	return int64(n), nil
}

// Accept implements the linux syscall accept(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketVFS2) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	// Issue the accept request to get the new endpoint.
	ep, wq, terr := s.Endpoint.Accept()
	if terr != nil {
		if terr != tcpip.ErrWouldBlock || !blocking {
			return 0, nil, 0, syserr.TranslateNetstackError(terr)
		}

		var err *syserr.Error
		ep, wq, err = s.blockingAccept(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns, err := NewVFS2(t, s.family, s.skType, s.protocol, wq, ep)
	if err != nil {
		return 0, nil, 0, err
	}
	defer ns.DecRef()

	if err := ns.SetStatusFlags(t, t.Credentials(), uint32(flags&linux.SOCK_NONBLOCK)); err != nil {
		return 0, nil, 0, syserr.FromError(err)
	}

	var addr linux.SockAddr
	var addrLen uint32
	if peerRequested {
		// Get address of the peer and write it to peer slice.
		var err *syserr.Error
		addr, addrLen, err = ns.Impl().(*SocketVFS2).GetPeerName(t)
		if err != nil {
			return 0, nil, 0, err
		}
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
func (s *SocketVFS2) GetSockOpt(t *kernel.Task, level, name int, outPtr usermem.Addr, outLen int) (interface{}, *syserr.Error) {
	// TODO(b/78348848): Unlike other socket options, SO_TIMESTAMP is
	// implemented specifically for netstack.SocketVFS2 rather than
	// commonEndpoint. commonEndpoint should be extended to support socket
	// options where the implementation is not shared, as unix sockets need
	// their own support for SO_TIMESTAMP.
	if level == linux.SOL_SOCKET && name == linux.SO_TIMESTAMP {
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}
		val := int32(0)
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.sockOptTimestamp {
			val = 1
		}
		return val, nil
	}
	if level == linux.SOL_TCP && name == linux.TCP_INQ {
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}
		val := int32(0)
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.sockOptInq {
			val = 1
		}
		return val, nil
	}

	if s.skType == linux.SOCK_RAW && level == linux.IPPROTO_IP {
		switch name {
		case linux.IPT_SO_GET_INFO:
			if outLen < linux.SizeOfIPTGetinfo {
				return nil, syserr.ErrInvalidArgument
			}

			stack := inet.StackFromContext(t)
			if stack == nil {
				return nil, syserr.ErrNoDevice
			}
			info, err := netfilter.GetInfo(t, stack.(*Stack).Stack, outPtr)
			if err != nil {
				return nil, err
			}
			return info, nil

		case linux.IPT_SO_GET_ENTRIES:
			if outLen < linux.SizeOfIPTGetEntries {
				return nil, syserr.ErrInvalidArgument
			}

			stack := inet.StackFromContext(t)
			if stack == nil {
				return nil, syserr.ErrNoDevice
			}
			entries, err := netfilter.GetEntries(t, stack.(*Stack).Stack, outPtr, outLen)
			if err != nil {
				return nil, err
			}
			return entries, nil

		}
	}

	return GetSockOpt(t, s, s.Endpoint, s.family, s.skType, level, name, outLen)
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
		s.sockOptTimestamp = usermem.ByteOrder.Uint32(optVal) != 0
		return nil
	}
	if level == linux.SOL_TCP && name == linux.TCP_INQ {
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		s.readMu.Lock()
		defer s.readMu.Unlock()
		s.sockOptInq = usermem.ByteOrder.Uint32(optVal) != 0
		return nil
	}

	if s.skType == linux.SOCK_RAW && level == linux.IPPROTO_IP {
		switch name {
		case linux.IPT_SO_SET_REPLACE:
			if len(optVal) < linux.SizeOfIPTReplace {
				return syserr.ErrInvalidArgument
			}

			stack := inet.StackFromContext(t)
			if stack == nil {
				return syserr.ErrNoDevice
			}
			// Stack must be a netstack stack.
			return netfilter.SetEntries(stack.(*Stack).Stack, optVal)

		case linux.IPT_SO_SET_ADD_COUNTERS:
			// TODO(gvisor.dev/issue/170): Counter support.
			return nil
		}
	}

	return SetSockOpt(t, s, s.Endpoint, level, name, optVal)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (s *SocketVFS2) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return s.Locks().LockPOSIX(ctx, &s.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (s *SocketVFS2) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return s.Locks().UnlockPOSIX(ctx, &s.vfsfd, uid, start, length, whence)
}
