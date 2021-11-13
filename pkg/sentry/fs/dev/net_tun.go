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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
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
func (*netTunInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
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
func (n *netTunFileOperations) Release(ctx context.Context) {
	n.device.Release(ctx)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (n *netTunFileOperations) Ioctl(ctx context.Context, file *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	request := args[1].Uint()
	data := args[2].Pointer()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}

	switch request {
	case linux.TUNSETIFF:
		if !t.HasCapability(linux.CAP_NET_ADMIN) {
			return 0, linuxerr.EPERM
		}
		stack, ok := t.NetworkContext().(*netstack.Stack)
		if !ok {
			return 0, linuxerr.EINVAL
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
		return 0, n.device.SetIff(stack.Stack, req.Name(), flags)

	case linux.TUNGETIFF:
		var req linux.IFReq
		copy(req.IFName[:], n.device.Name())
		hostarch.ByteOrder.PutUint16(req.Data[:], netstack.TUNFlagsToLinux(n.device.Flags()))
		_, err := req.CopyOut(t, data)
		return 0, err

	default:
		return 0, linuxerr.ENOTTY
	}
}

// Write implements fs.FileOperations.Write.
func (n *netTunFileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	return n.device.Write(data)
}

// Read implements fs.FileOperations.Read.
func (n *netTunFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	data, err := n.device.Read()
	if err != nil {
		return 0, err
	}
	bytesCopied, err := dst.CopyOut(ctx, data)
	if bytesCopied > 0 && bytesCopied < len(data) {
		// Not an error for partial copying. Packet truncated.
		err = nil
	}
	return int64(bytesCopied), err
}

// Readiness implements watier.Waitable.Readiness.
func (n *netTunFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return n.device.Readiness(mask)
}

// EventRegister implements watier.Waitable.EventRegister.
func (n *netTunFileOperations) EventRegister(e *waiter.Entry) {
	n.device.EventRegister(e)
}

// EventUnregister implements watier.Waitable.EventUnregister.
func (n *netTunFileOperations) EventUnregister(e *waiter.Entry) {
	n.device.EventUnregister(e)
}

// isNetTunSupported returns whether /dev/net/tun device is supported for s.
func isNetTunSupported(s inet.Stack) bool {
	_, ok := s.(*netstack.Stack)
	return ok
}
