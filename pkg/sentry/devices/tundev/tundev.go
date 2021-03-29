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

// Package tundev implements the /dev/net/tun device.
package tundev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	netTunDevMajor = 10
	netTunDevMinor = 200
)

// tunDevice implements vfs.Device for /dev/net/tun.
//
// +stateify savable
type tunDevice struct{}

// Open implements vfs.Device.Open.
func (tunDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &tunFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// tunFD implements vfs.FileDescriptionImpl for /dev/net/tun.
//
// +stateify savable
type tunFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	device tun.Device
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *tunFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	request := args[1].Uint()
	data := args[2].Pointer()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}

	switch request {
	case linux.TUNSETIFF:
		if !t.HasCapability(linux.CAP_NET_ADMIN) {
			return 0, syserror.EPERM
		}
		stack, ok := t.NetworkContext().(*netstack.Stack)
		if !ok {
			return 0, syserror.EINVAL
		}

		var req linux.IFReq
		if _, err := req.CopyIn(t, data); err != nil {
			return 0, err
		}

		// Validate flags.
		flags, err := netstack.LinuxToTUNFlags(hostarch.ByteOrder.Uint16(req.Data[:]))
		if err != nil {
			return 0, err
		}
		return 0, fd.device.SetIff(stack.Stack, req.Name(), flags)

	case linux.TUNGETIFF:
		var req linux.IFReq
		copy(req.IFName[:], fd.device.Name())
		hostarch.ByteOrder.PutUint16(req.Data[:], netstack.TUNFlagsToLinux(fd.device.Flags()))
		_, err := req.CopyOut(t, data)
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *tunFD) Release(ctx context.Context) {
	fd.device.Release(ctx)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *tunFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.Read(ctx, dst, opts)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *tunFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	data, err := fd.device.Read()
	if err != nil {
		return 0, err
	}
	n, err := dst.CopyOut(ctx, data)
	if n > 0 && n < len(data) {
		// Not an error for partial copying. Packet truncated.
		err = nil
	}
	return int64(n), err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *tunFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return fd.Write(ctx, src, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *tunFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	return fd.device.Write(data)
}

// Readiness implements watier.Waitable.Readiness.
func (fd *tunFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fd.device.Readiness(mask)
}

// EventRegister implements watier.Waitable.EventRegister.
func (fd *tunFD) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	fd.device.EventRegister(e, mask)
}

// EventUnregister implements watier.Waitable.EventUnregister.
func (fd *tunFD) EventUnregister(e *waiter.Entry) {
	fd.device.EventUnregister(e)
}

// IsNetTunSupported returns whether /dev/net/tun device is supported for s.
func IsNetTunSupported(s inet.Stack) bool {
	_, ok := s.(*netstack.Stack)
	return ok
}

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, netTunDevMajor, netTunDevMinor, tunDevice{}, &vfs.RegisterDeviceOptions{})
}

// CreateDevtmpfsFiles creates device special files in dev representing all
// devices implemented by this package.
func CreateDevtmpfsFiles(ctx context.Context, dev *devtmpfs.Accessor) error {
	return dev.CreateDeviceFile(ctx, "net/tun", vfs.CharDevice, netTunDevMajor, netTunDevMinor, 0666 /* mode */)
}
