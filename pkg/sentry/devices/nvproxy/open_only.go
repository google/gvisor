// Copyright 2026 The gVisor Authors.
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

package nvproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// openOnlyDevice implements vfs.Device for devices that can only be opened
// (nothing can be done with the opened file description except for passing it
// to nvproxy ioctls on other files).
//
// +stateify savable
type openOnlyDevice struct {
	nvp     *nvproxy
	relpath string
}

// Open implements vfs.Device.Open.
func (dev *openOnlyDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &openOnlyFD{
		dev: dev,
	}
	var err error
	fd.hostFD, fd.containerName, err = openHostDevFile(ctx, dev.relpath, dev.nvp.useDevGofer, opts.Flags)
	if err != nil {
		return nil, err
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(int(fd.hostFD))
		return nil, err
	}
	return &fd.vfsfd, nil
}

// openOnlyFD implements vfs.FileDescriptionImpl for openOnlyDevice.
type openOnlyFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	dev           *openOnlyDevice
	containerName string
	hostFD        int32
}

// IsNvidiaDeviceFD implements NvidiaDeviceFD.IsNvidiaDeviceFD.
func (fd *openOnlyFD) IsNvidiaDeviceFD() {}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *openOnlyFD) Release(ctx context.Context) {
	unix.Close(int(fd.hostFD))
}
