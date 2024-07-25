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
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// VFIO_MINOR is the VFIO minor number from include/linux/miscdevice.h.
	VFIO_MINOR = 196

	// VFIOPath is the path to a VFIO device, it is usually used to
	// construct a VFIO container.
	VFIOPath = "/dev/vfio/vfio"

	tpuDeviceGroupName  = "vfio"
	vfioDeviceGroupName = "vfio"
)

// device implements TPU's vfs.Device for /dev/vfio/[0-9]+
//
// +stateify savable
type tpuDevice struct {
	mu sync.Mutex

	// minor is the device minor number.
	minor uint32
	// num is the number of the device in the dev filesystem (e.g /dev/vfio/0).
	num uint32
}

// Open implements vfs.Device.Open.
func (dev *tpuDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devClient := devutil.GoferClientFromContext(ctx)
	if devClient == nil {
		log.Warningf("devutil.CtxDevGoferClient is not set")
		return nil, linuxerr.ENOENT
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	devName := filepath.Join("vfio", strconv.Itoa(int(dev.num)))
	hostFD, err := devClient.OpenAt(ctx, devName, opts.Flags)
	if err != nil {
		ctx.Warningf("tpuDevice: failed to open host %s: %v", devName, err)
		return nil, err
	}
	fd := &tpuFD{
		hostFD: int32(hostFD),
		device: dev,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.fd = fd
	return &fd.vfsfd, nil
}

// device implements vfs.Device for /dev/vfio/vfio.
type vfioDevice struct{}

// Open implements vfs.Device.Open.
func (dev *vfioDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	client := devutil.GoferClientFromContext(ctx)
	if client == nil {
		log.Warningf("devutil.CtxDevGoferClient is not set")
		return nil, linuxerr.ENOENT
	}

	name := filepath.Join("vfio", filepath.Base(VFIOPath))
	hostFD, err := client.OpenAt(ctx, name, opts.Flags)
	if err != nil {
		ctx.Warningf("failed to open host file %s: %v", name, err)
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
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.fd = fd
	return &fd.vfsfd, nil
}

// RegisterTPUDevice registers devices implemented by this package in vfsObj.
func RegisterTPUDevice(vfsObj *vfs.VirtualFilesystem, minor, deviceNum uint32) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.VFIO_MAJOR, minor, &tpuDevice{
		minor: minor,
		num:   deviceNum,
	}, &vfs.RegisterDeviceOptions{
		GroupName: tpuDeviceGroupName,
	})
}

// RegisterVfioDevice registers VFIO devices that are implemented by this package in vfsObj.
func RegisterVfioDevice(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.MISC_MAJOR, VFIO_MINOR, &vfioDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: vfioDeviceGroupName,
	})
}
