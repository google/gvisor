// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpuproxy

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	tpuDeviceGroupName = "vfio"
)

// vfioDevice implements vfs.Device for /dev/vfio/[0-9]+
//
// +stateify savable
type vfioDevice struct {
	mu sync.Mutex

	minor uint32
}

// Open implememnts vfs.Device.Open.
func (dev *vfioDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devClient := devutil.GoferClientFromContext(ctx)
	if devClient == nil {
		log.Warningf("devutil.CtxDevGoferClient is not set")
		return nil, linuxerr.ENOENT
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	devName := fmt.Sprintf("/dev/vfio/%d", dev.minor)
	hostFD, err := devClient.OpenAt(ctx, devName, opts.Flags)
	if err != nil {
		ctx.Warningf("vfioDevice: failed to open host %s: %v", devName, err)
		return nil, err
	}
	fd := &vfioFD{
		hostFD: int32(hostFD),
		device: dev,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// RegisterTPUDevice registers devices implemented by this package in vfsObj.
func RegisterTPUDevice(vfsObj *vfs.VirtualFilesystem, minor uint32) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.VFIO_MAJOR, minor, &vfioDevice{
		minor: minor,
	}, &vfs.RegisterDeviceOptions{
		GroupName: tpuDeviceGroupName,
	})
}
