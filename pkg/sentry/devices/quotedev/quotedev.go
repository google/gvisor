// Copyright 2021 The gVisor Authors.
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

// Package quotedev implements a vfs.Device for /dev/gvisor_quote.
package quotedev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	quoteDevMinor = 0
)

// quoteDevice implements vfs.Device for /dev/gvisor_quote
//
// +stateify savable
type quoteDevice struct{}

// Open implements vfs.Device.Open.
// TODO(b/157161182): Add support for attestation ioctls.
func (quoteDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, linuxerr.EIO
}

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.UNNAMED_MAJOR, quoteDevMinor, quoteDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: "gvisor_quote",
	})
}

// CreateDevtmpfsFiles creates device special files in dev representing all
// devices implemented by this package.
func CreateDevtmpfsFiles(ctx context.Context, dev *devtmpfs.Accessor) error {
	return dev.CreateDeviceFile(ctx, "gvisor_quote", vfs.CharDevice, linux.UNNAMED_MAJOR, quoteDevMinor, 0666 /* mode */)
}
