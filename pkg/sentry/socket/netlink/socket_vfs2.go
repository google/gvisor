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

package netlink

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SocketVFS2 is the base VFS2 socket type for netlink sockets.
//
// This implementation only supports userspace sending and receiving messages
// to/from the kernel.
//
// SocketVFS2 implements socket.SocketVFS2 and transport.Credentialer.
//
// +stateify savable
type SocketVFS2 struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD

	socketOpsCommon
}

var _ socket.SocketVFS2 = (*SocketVFS2)(nil)
var _ transport.Credentialer = (*SocketVFS2)(nil)

// NewVFS2 creates a new SocketVFS2.
func NewVFS2(t *kernel.Task, skType linux.SockType, protocol Protocol) (*SocketVFS2, *syserr.Error) {
	// Datagram endpoint used to buffer kernel -> user messages.
	ep := transport.NewConnectionless(t)

	// Bind the endpoint for good measure so we can connect to it. The
	// bound address will never be exposed.
	if err := ep.Bind(tcpip.FullAddress{Addr: "dummy"}, nil); err != nil {
		ep.Close(t)
		return nil, err
	}

	// Create a connection from which the kernel can write messages.
	connection, err := ep.(transport.BoundEndpoint).UnidirectionalConnect(t)
	if err != nil {
		ep.Close(t)
		return nil, err
	}

	fd := &SocketVFS2{
		socketOpsCommon: socketOpsCommon{
			ports:          t.Kernel().NetlinkPorts(),
			protocol:       protocol,
			skType:         skType,
			ep:             ep,
			connection:     connection,
			sendBufferSize: defaultSendBufferSize,
		},
	}
	fd.LockFD.Init(&vfs.FileLocks{})
	return fd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (s *SocketVFS2) Release(ctx context.Context) {
	t := kernel.TaskFromContext(ctx)
	t.Kernel().DeleteSocketVFS2(&s.vfsfd)
	s.socketOpsCommon.Release(ctx)
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

// Ioctl implements vfs.FileDescriptionImpl.
func (*SocketVFS2) Ioctl(context.Context, usermem.IO, arch.SyscallArguments) (uintptr, error) {
	// TODO(b/68878065): no ioctls supported.
	return 0, syserror.ENOTTY
}

// PRead implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.ESPIPE
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
	return dst.CopyOutFrom(ctx, &unix.EndpointReader{
		Endpoint: s.ep,
	})
}

// PWrite implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.
func (s *SocketVFS2) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	n, err := s.sendMsg(ctx, src, nil, 0, socket.ControlMessages{})
	return int64(n), err.ToError()
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (s *SocketVFS2) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return s.Locks().LockPOSIX(ctx, &s.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (s *SocketVFS2) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return s.Locks().UnlockPOSIX(ctx, &s.vfsfd, uid, start, length, whence)
}
