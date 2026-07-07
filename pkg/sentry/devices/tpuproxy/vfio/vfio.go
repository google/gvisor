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

package vfio

import (
	"fmt"
	"path"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// VFIO_MINOR is the VFIO minor number from include/linux/miscdevice.h.
	VFIO_MINOR = 196

	tpuDeviceGroupName  = "vfio"
	vfioDeviceGroupName = "vfio"
)

var (
	tpuDeviceMajor        uint32
	tpuDeviceMajorInit    sync.Once
	tpuDeviceMajorInitErr error
)

// +stateify savable
type tpuproxy struct {
	mu      sync.Mutex                           `state:"nosave"`
	openFDs map[vfs.FileDescriptionImpl]struct{} `state:"nosave"`
}

func (t *tpuproxy) trackFD(fd vfs.FileDescriptionImpl) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.openFDs == nil {
		t.openFDs = make(map[vfs.FileDescriptionImpl]struct{})
	}
	t.openFDs[fd] = struct{}{}
}

func (t *tpuproxy) untrackFD(fd vfs.FileDescriptionImpl) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.openFDs != nil {
		delete(t.openFDs, fd)
	}
}

// AnyDevicesOpen returns true if any TPU/VFIO FDs are currently open.
func AnyDevicesOpen(vfsObj *vfs.VirtualFilesystem) bool {
	tpuproxy := tpuproxyFromVFS(vfsObj)
	if tpuproxy == nil {
		return false
	}
	tpuproxy.mu.Lock()
	defer tpuproxy.mu.Unlock()
	return len(tpuproxy.openFDs) != 0
}

// device implements TPU's vfs.Device for /dev/vfio/[0-9]+
//
// +stateify savable
type tpuDevice struct {
	mu sync.Mutex `state:"nosave"`

	// minor is the device minor number.
	minor uint32
	// num is the number of the device in the dev filesystem (e.g /dev/vfio/0).
	num uint32
	// useDevGofer indicates whether to use device gofer to open the TPU device.
	useDevGofer bool
	// tpuproxy is the TPU proxy object.
	tpuproxy *tpuproxy
}

// Open implements vfs.Device.Open.
func (dev *tpuDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	dev.mu.Lock()
	defer dev.mu.Unlock()

	devPath := filepath.Join("vfio", strconv.Itoa(int(dev.num)))
	hostFD, containerName, err := openHostFD(ctx, devPath, opts.Flags, dev.useDevGofer)
	if err != nil {
		return nil, err
	}

	fd := &tpuFD{
		hostFD:        int32(hostFD),
		containerName: containerName,
		device:        dev,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.SetFD(hostFD)
	dev.tpuproxy.trackFD(fd)
	return &fd.vfsfd, nil
}

// device implements vfs.Device for /dev/vfio/vfio.
//
// +stateify savable
type vfioDevice struct {
	// useDevGofer indicates whether to use device gofer to open the VFIO device.
	useDevGofer bool
	// tpuproxy is the TPU proxy object.
	tpuproxy *tpuproxy
}

// Open implements vfs.Device.Open.
func (dev *vfioDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devPath := filepath.Join("vfio", "vfio")
	hostFD, containerName, err := openHostFD(ctx, devPath, opts.Flags, dev.useDevGofer)
	if err != nil {
		return nil, err
	}
	fd := &vfioFD{
		hostFD:        int32(hostFD),
		containerName: containerName,
		device:        dev,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.SetFD(hostFD)
	dev.tpuproxy.trackFD(fd)
	return &fd.vfsfd, nil
}

// Register registers the VFIO control device and creates the tpuproxy object.
func Register(vfsObj *vfs.VirtualFilesystem, useDevGofer bool) error {
	if vfsObj.IsDeviceRegistered(vfs.CharDevice, linux.MISC_MAJOR, VFIO_MINOR) {
		return nil
	}
	tpuproxy := &tpuproxy{
		openFDs: make(map[vfs.FileDescriptionImpl]struct{}),
	}
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.MISC_MAJOR, VFIO_MINOR, &vfioDevice{
		useDevGofer: useDevGofer,
		tpuproxy:    tpuproxy,
	}, &vfs.RegisterDeviceOptions{
		GroupName: vfioDeviceGroupName,
		Pathname:  path.Join("vfio", "vfio"),
		FilePerms: 0666,
	})
}

// RegisterTPUDevice registers devices implemented by this package in vfsObj.
func RegisterTPUDevice(vfsObj *vfs.VirtualFilesystem, minor, deviceNum uint32, useDevGofer bool) error {
	tpuproxy := tpuproxyFromVFS(vfsObj)
	if tpuproxy == nil {
		return fmt.Errorf("vfio.Register must be called before RegisterTPUDevice")
	}
	major, err := GetTPUDeviceMajor(vfsObj)
	if err != nil {
		return err
	}
	if vfsObj.IsDeviceRegistered(vfs.CharDevice, major, minor) {
		return nil
	}
	return vfsObj.RegisterDevice(vfs.CharDevice, major, minor, &tpuDevice{
		minor:       minor,
		num:         deviceNum,
		useDevGofer: useDevGofer,
		tpuproxy:    tpuproxy,
	}, &vfs.RegisterDeviceOptions{
		GroupName: tpuDeviceGroupName,
		Pathname:  path.Join("vfio", strconv.Itoa(int(deviceNum))),
		FilePerms: 0666,
	})
}

func tpuproxyFromVFS(vfsObj *vfs.VirtualFilesystem) *tpuproxy {
	devAny := vfsObj.GetRegisteredDevice(vfs.CharDevice, linux.MISC_MAJOR, VFIO_MINOR)
	if devAny == nil {
		return nil
	}
	dev, ok := devAny.(*vfioDevice)
	if !ok {
		return nil
	}
	return dev.tpuproxy
}

func openHostFD(ctx context.Context, devName string, flags uint32, useDevGofer bool) (int, string, error) {
	if useDevGofer {
		client := devutil.GoferClientFromContext(ctx)
		if client == nil {
			log.Warningf("devutil.CtxDevGoferClient is not set")
			return -1, "", linuxerr.ENOENT
		}
		fd, err := client.OpenAt(ctx, devName, flags)
		return fd, client.ContainerName(), err
	}
	devPath := filepath.Join("/", "dev", devName)
	openFlags := int(flags&unix.O_ACCMODE | unix.O_NOFOLLOW)
	fd, err := unix.Openat(-1, devPath, openFlags, 0)
	return fd, "", err
}

// GetTPUDeviceMajor returns the dynamically allocated major number for the vfio
// device.
func GetTPUDeviceMajor(vfsObj *vfs.VirtualFilesystem) (uint32, error) {
	tpuDeviceMajorInit.Do(func() {
		tpuDeviceMajor, tpuDeviceMajorInitErr = vfsObj.GetDynamicCharDevMajor()
	})
	return tpuDeviceMajor, tpuDeviceMajorInitErr
}

// IsVFIOFD returns true if the file description implementation is a TPU VFIO FD.
func IsVFIOFD(fd vfs.FileDescriptionImpl) bool {
	switch fd.(type) {
	case *tpuFD, *vfioFD, *pciDeviceFD:
		return true
	}
	return false
}
