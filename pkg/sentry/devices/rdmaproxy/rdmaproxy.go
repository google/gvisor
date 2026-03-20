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

// Package rdmaproxy implements a passthrough proxy for /dev/infiniband/uverbs*
// devices, enabling RDMA support inside gVisor sandboxes.
package rdmaproxy

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// uverbsDevice implements vfs.Device for /dev/infiniband/uverbs*.
type uverbsDevice struct {
	minor uint32
}

// Open implements vfs.Device.Open.
func (dev *uverbsDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	hostPath := filepath.Join("/dev/infiniband", fmt.Sprintf("uverbs%d", dev.minor))
	openFlags := int(opts.Flags&unix.O_ACCMODE | unix.O_NOFOLLOW)
	hostFD, err := unix.Openat(-1, hostPath, openFlags, 0)
	if err != nil {
		log.Warningf("rdmaproxy: failed to open host device %s: %v", hostPath, err)
		return nil, err
	}
	fd := &uverbsFD{
		hostFD: int32(hostFD),
	}
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.SetFD(int(fd.hostFD))
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		fdnotifier.RemoveFD(fd.hostFD)
		unix.Close(hostFD)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// uverbsFD implements vfs.FileDescriptionImpl for an opened uverbs device.
//
// uverbsFD is not savable; we do not implement save/restore of RDMA state.
type uverbsFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	memmap.MappableNoTrackMappings

	hostFD     int32
	queue      waiter.Queue
	memmapFile fsutil.MmapNoInternalFile
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *uverbsFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *uverbsFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *uverbsFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *uverbsFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Register registers /dev/infiniband/uverbs[minor] with the VFS and returns
// the dynamic major number assigned to it.
func Register(vfsObj *vfs.VirtualFilesystem, minor uint32) (uint32, error) {
	major, err := vfsObj.GetDynamicCharDevMajor()
	if err != nil {
		return 0, fmt.Errorf("rdmaproxy: obtaining dynamic major number: %w", err)
	}
	if err := vfsObj.RegisterDevice(vfs.CharDevice, major, minor, &uverbsDevice{minor: minor}, &vfs.RegisterDeviceOptions{
		GroupName: "infiniband",
		Pathname:  fmt.Sprintf("infiniband/uverbs%d", minor),
		FilePerms: 0666,
	}); err != nil {
		return 0, err
	}
	return major, nil
}

// MayRegisterDevicePath returns true if path looks like a uverbs device.
func MayRegisterDevicePath(path string) bool {
	matched, _ := filepath.Match("/dev/infiniband/uverbs*", path)
	return matched
}

// ErrNotUverbsDevice is returned when the device path doesn't match.
var ErrNotUverbsDevice = linuxerr.ENODEV
