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

// Package ttydev implements devices for /dev/tty and (eventually)
// /dev/console.
//
// TODO(b/159623826): Support /dev/console.
package ttydev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// See drivers/tty/tty_io.c:tty_init().
	ttyDevMinor     = 0
	consoleDevMinor = 1
)

// ttyDevice implements vfs.Device for /dev/tty.
type ttyDevice struct{}

// Open implements vfs.Device.Open.
func (ttyDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &ttyFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// ttyFD implements vfs.FileDescriptionImpl for /dev/tty.
type ttyFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *ttyFD) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *ttyFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *ttyFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *ttyFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return src.NumBytes(), nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *ttyFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return src.NumBytes(), nil
}

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.TTYAUX_MAJOR, ttyDevMinor, ttyDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: "tty",
	})
}

// CreateDevtmpfsFiles creates device special files in dev representing all
// devices implemented by this package.
func CreateDevtmpfsFiles(ctx context.Context, dev *devtmpfs.Accessor) error {
	return dev.CreateDeviceFile(ctx, "tty", vfs.CharDevice, linux.TTYAUX_MAJOR, ttyDevMinor, 0666 /* mode */)
}
