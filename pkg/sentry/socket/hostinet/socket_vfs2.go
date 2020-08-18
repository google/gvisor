// Copyright 2020 The gVisor Authors.
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

package hostinet

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

type socketVFS2 struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	// We store metadata for hostinet sockets internally. Technically, we should
	// access metadata (e.g. through stat, chmod) on the host for correctness,
	// but this is not very useful for inet socket fds, which do not belong to a
	// concrete file anyway.
	vfs.DentryMetadataFileDescriptionImpl

	socketOpsCommon
}

var _ = socket.SocketVFS2(&socketVFS2{})

func newVFS2Socket(t *kernel.Task, family int, stype linux.SockType, protocol int, fd int, flags uint32) (*vfs.FileDescription, *syserr.Error) {
	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t.Credentials(), mnt)

	s := &socketVFS2{
		socketOpsCommon: socketOpsCommon{
			family:   family,
			stype:    stype,
			protocol: protocol,
			fd:       fd,
		},
	}
	s.LockFD.Init(&vfs.FileLocks{})
	if err := fdnotifier.AddFD(int32(fd), &s.queue); err != nil {
		return nil, syserr.FromError(err)
	}
	vfsfd := &s.vfsfd
	if err := vfsfd.Init(s, linux.O_RDWR|(flags&linux.O_NONBLOCK), mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		fdnotifier.RemoveFD(int32(s.fd))
		return nil, syserr.FromError(err)
	}
	return vfsfd, nil
}

// Readiness implements waiter.Waitable.Readiness.
func (s *socketVFS2) Readiness(mask waiter.EventMask) waiter.EventMask {
	return s.socketOpsCommon.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *socketVFS2) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.socketOpsCommon.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *socketVFS2) EventUnregister(e *waiter.Entry) {
	s.socketOpsCommon.EventUnregister(e)
}

// Ioctl implements vfs.FileDescriptionImpl.
func (s *socketVFS2) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return ioctl(ctx, s.fd, uio, args)
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (s *socketVFS2) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return syserror.ENODEV
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (s *socketVFS2) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// Read implements vfs.FileDescriptionImpl.
func (s *socketVFS2) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	reader := hostfd.GetReadWriterAt(int32(s.fd), -1, opts.Flags)
	n, err := dst.CopyOutFrom(ctx, reader)
	hostfd.PutReadWriterAt(reader)
	return int64(n), err
}

// PWrite implements vfs.FileDescriptionImpl.
func (s *socketVFS2) PWrite(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.
func (s *socketVFS2) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// All flags other than RWF_NOWAIT should be ignored.
	// TODO(gvisor.dev/issue/2601): Support RWF_NOWAIT.
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	writer := hostfd.GetReadWriterAt(int32(s.fd), -1, opts.Flags)
	n, err := src.CopyInTo(ctx, writer)
	hostfd.PutReadWriterAt(writer)
	return int64(n), err
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (s *socketVFS2) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return s.Locks().LockPOSIX(ctx, &s.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (s *socketVFS2) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return s.Locks().UnlockPOSIX(ctx, &s.vfsfd, uid, start, length, whence)
}

type socketProviderVFS2 struct {
	family int
}

// Socket implements socket.ProviderVFS2.Socket.
func (p *socketProviderVFS2) Socket(t *kernel.Task, stypeflags linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Check that we are using the host network stack.
	stack := t.NetworkContext()
	if stack == nil {
		return nil, nil
	}
	if _, ok := stack.(*Stack); !ok {
		return nil, nil
	}

	// Only accept TCP and UDP.
	stype := stypeflags & linux.SOCK_TYPE_MASK
	switch stype {
	case syscall.SOCK_STREAM:
		switch protocol {
		case 0, syscall.IPPROTO_TCP:
			// ok
		default:
			return nil, nil
		}
	case syscall.SOCK_DGRAM:
		switch protocol {
		case 0, syscall.IPPROTO_UDP:
			// ok
		default:
			return nil, nil
		}
	default:
		return nil, nil
	}

	// Conservatively ignore all flags specified by the application and add
	// SOCK_NONBLOCK since socketOperations requires it. Pass a protocol of 0
	// to simplify the syscall filters, since 0 and IPPROTO_* are equivalent.
	fd, err := syscall.Socket(p.family, int(stype)|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, syserr.FromError(err)
	}
	return newVFS2Socket(t, p.family, stype, protocol, fd, uint32(stypeflags&syscall.SOCK_NONBLOCK))
}

// Pair implements socket.Provider.Pair.
func (p *socketProviderVFS2) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	// Not supported by AF_INET/AF_INET6.
	return nil, nil, nil
}
