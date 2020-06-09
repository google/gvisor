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

package miscdev

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

const fuseDevMinor = 229

// fuseDevice implements vfs.Device for /dev/fuse.
type fuseDevice struct{}

// Open implements vfs.Device.Open.
func (fuseDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	var fd FUSEDeviceFile
	if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// FUSEDeviceFile implements vfs.FileDescriptionImpl for /dev/fuse.
type FUSEDeviceFile struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// TODO(gvisor.dev/issue/2987): Add all the data structures needed to enqueue
	// and deque requests, control synchronization and establish communication
	// between the FUSE kernel module and the /dev/fuse character device.
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *FUSEDeviceFile) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *FUSEDeviceFile) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *FUSEDeviceFile) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *FUSEDeviceFile) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *FUSEDeviceFile) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.ENOSYS
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *FUSEDeviceFile) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, syserror.ENOSYS
}
