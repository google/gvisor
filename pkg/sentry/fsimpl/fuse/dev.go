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

package fuse

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

const fuseDevMinor = 229

// fuseDevice implements vfs.Device for /dev/fuse.
type fuseDevice struct{}

// Open implements vfs.Device.Open.
func (fuseDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if !kernel.FUSEEnabled {
		return nil, syserror.ENOENT
	}

	var fd DeviceFD
	if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// DeviceFD implements vfs.FileDescriptionImpl for /dev/fuse.
type DeviceFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// TODO(gvisor.dev/issue/2987): Add all the data structures needed to enqueue
	// and deque requests, control synchronization and establish communication
	// between the FUSE kernel module and the /dev/fuse character device.
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *DeviceFD) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *DeviceFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *DeviceFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *DeviceFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *DeviceFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DeviceFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, syserror.ENOSYS
}

// Register registers the FUSE device with vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	if err := vfsObj.RegisterDevice(vfs.CharDevice, linux.MISC_MAJOR, fuseDevMinor, fuseDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: "misc",
	}); err != nil {
		return err
	}

	return nil
}

// CreateDevtmpfsFile creates a device special file in devtmpfs.
func CreateDevtmpfsFile(ctx context.Context, dev *devtmpfs.Accessor) error {
	if err := dev.CreateDeviceFile(ctx, "fuse", vfs.CharDevice, linux.MISC_MAJOR, fuseDevMinor, 0666 /* mode */); err != nil {
		return err
	}

	return nil
}
