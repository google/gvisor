// Copyright 2024 The gVisor Authors.
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

package rdmaproxy

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
//
// This is a pure passthrough: copy the ioctl arg buffer from the sandboxed
// process, forward the ioctl to the host device, and copy results back.
func (fd *uverbsFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	argPtr := args[2].Pointer()
	argSize := ioctl_SIZE(cmd)

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("rdmaproxy: ioctl called without task context")
		return 0, unix.EINVAL
	}

	if argSize == 0 || argPtr == 0 {
		// No-arg ioctl, forward directly.
		n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd.hostFD), uintptr(cmd), 0)
		if errno != 0 {
			return n, errno
		}
		return n, nil
	}

	// Copy ioctl argument buffer from sandbox userspace.
	buf := make([]byte, argSize)
	if _, err := t.CopyInBytes(argPtr, buf); err != nil {
		return 0, err
	}

	// Forward ioctl to the host device.
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd.hostFD), uintptr(cmd), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return n, errno
	}

	// Copy results back to sandbox userspace.
	if _, err := t.CopyOutBytes(argPtr, buf); err != nil {
		return 0, err
	}
	return n, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *uverbsFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
}

// Translate implements memmap.Mappable.Translate.
func (fd *uverbsFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   &fd.memmapFile,
			Offset: optional.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}

// ioctl_SIZE extracts the size field from a Linux ioctl command number.
func ioctl_SIZE(cmd uint32) uint32 {
	return (cmd >> 16) & 0x3FFF
}
