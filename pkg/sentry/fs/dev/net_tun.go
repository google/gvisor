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

package dev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	netTunDevMajor = 10
	netTunDevMinor = 200
)

// +stateify savable
type netTunInodeOperations struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopAllocate         `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
}

var _ fs.InodeOperations = (*netTunInodeOperations)(nil)

func newNetTunDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *netTunInodeOperations {
	return &netTunInodeOperations{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
	}
}

// GetFile implements fs.InodeOperations.GetFile.
func (iops *netTunInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &netTunFileOperations{}), nil
}

// +stateify savable
type netTunFileOperations struct {
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	device tun.Device
}

var _ fs.FileOperations = (*netTunFileOperations)(nil)

// Release implements fs.FileOperations.Release.
func (fops *netTunFileOperations) Release() {
	fops.device.Release()
}

// Ioctl implements fs.FileOperations.Ioctl.
func (fops *netTunFileOperations) Ioctl(ctx context.Context, file *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	request := args[1].Uint()
	data := args[2].Pointer()

	switch request {
	case linux.TUNSETIFF:
		t := kernel.TaskFromContext(ctx)
		if t == nil {
			panic("Ioctl should be called from a task context")
		}
		if !t.HasCapability(linux.CAP_NET_ADMIN) {
			return 0, syserror.EPERM
		}
		stack, ok := t.NetworkContext().(*netstack.Stack)
		if !ok {
			return 0, syserror.EINVAL
		}

		var req linux.IFReq
		if _, err := usermem.CopyObjectIn(ctx, io, data, &req, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		flags := usermem.ByteOrder.Uint16(req.Data[:])
		return 0, fops.device.SetIff(stack.Stack, req.Name(), flags)

	case linux.TUNGETIFF:
		var req linux.IFReq

		copy(req.IFName[:], fops.device.Name())

		// Linux adds IFF_NOFILTER (the same value as IFF_NO_PI unfortunately) when
		// there is no sk_filter. See __tun_chr_ioctl() in net/drivers/tun.c.
		flags := fops.device.Flags() | linux.IFF_NOFILTER
		usermem.ByteOrder.PutUint16(req.Data[:], flags)

		_, err := usermem.CopyObjectOut(ctx, io, data, &req, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}

// Write implements fs.FileOperations.Write.
func (fops *netTunFileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	return fops.device.Write(data)
}

// Read implements fs.FileOperations.Read.
func (fops *netTunFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	data, err := fops.device.Read()
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

// Readiness implements watier.Waitable.Readiness.
func (fops *netTunFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fops.device.Readiness(mask)
}

// EventRegister implements watier.Waitable.EventRegister.
func (fops *netTunFileOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	fops.device.EventRegister(e, mask)
}

// EventUnregister implements watier.Waitable.EventUnregister.
func (fops *netTunFileOperations) EventUnregister(e *waiter.Entry) {
	fops.device.EventUnregister(e)
}

// isNetTunSupported returns whether /dev/net/tun device is supported for s.
func isNetTunSupported(s inet.Stack) bool {
	_, ok := s.(*netstack.Stack)
	return ok
}
