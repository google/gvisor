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

package rdmaproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// rdmaCMDevice implements vfs.Device for /dev/infiniband/rdma_cm.
//
// +stateify savable
type rdmaCMDevice struct {
	mu sync.Mutex `state:"nosave"`

	// rdmap is state of the rdma proxy
	rdmap *rdmaproxy
	// minor is the device minor number.
	minor uint32
	// useDevGofer indicates whether to use device gofer to open the TPU device.
	useDevGofer bool
}

// Open implements vfs.Device.Open.
func (dev *rdmaCMDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devPath := "infiniband/rdma_cm"
	hostFD, err := openHostFD(ctx, devPath, opts.Flags, dev.useDevGofer)
	if err != nil {
		return nil, err
	}

	fd := &rdmaCMFD{
		hostFD: int32(hostFD),
		device: dev,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// RegisterRDMACMDevice registers all devices implemented by this package in vfsObj.
func RegisterRDMACMDevice(vfsObj *vfs.VirtualFilesystem, minor uint32, useDevGofer bool) error {
	if vfsObj.IsDeviceRegistered(vfs.CharDevice, linux.MISC_MAJOR, minor) {
		return nil
	}
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.MISC_MAJOR, minor, &rdmaCMDevice{
		minor:       minor,
		useDevGofer: useDevGofer,
	}, &vfs.RegisterDeviceOptions{
		GroupName: "misc",
		Pathname:  "infiniband/rdma_cm",
		FilePerms: 0666,
	})
}

