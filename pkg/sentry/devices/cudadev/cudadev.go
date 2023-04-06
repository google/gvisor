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

// Package cudadev implements an unopenable vfs.Device for /dev/cuda.
package cudadev

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Static major and minor numbers for the custom /dev/cuda device.
//
// This major device number was chosen arbitrarily using a random number
// generator to avoid conflicts.
const (
	cudaDevMajor = 3656
	cudaDevMinor = 0
)

// cudaDevice implements vfs.Device for /dev/cuda.
//
// +stateify savable
type cudaDevice struct{}

// Open implements vfs.Device.Open.
func (cudaDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &cudaFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// fullFD implements vfs.FileDescriptionImpl for /dev/cuda.
//
// +stateify savable
type cudaFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *cudaFD) Release(context.Context) {
	// noop
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *cudaFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return 0, linuxerr.ENOSYS // TODO
}

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, cudaDevMajor, cudaDevMinor, cudaDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: "cuda",
	})
}

// CreateDevtmpfsFiles creates device special files in dev representing all
// devices implemented by this package.
func CreateDevtmpfsFiles(ctx context.Context, dev *devtmpfs.Accessor) error {
	return dev.CreateDeviceFile(ctx, "cuda", vfs.CharDevice, cudaDevMajor, cudaDevMinor, 0666 /* mode */)
}
