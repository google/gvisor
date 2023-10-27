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

package accel

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// tpuV4Device implements vfs.Device for /dev/accel[0-9]+.
//
// +stateify savable
type tpuV4Device struct {
	mu sync.Mutex

	minor uint32
	lite  bool
	// +checklocks:mu
	openWriteFDs uint32
	// +checklocks:mu
	devAddrSet DevAddrSet
	// +checklocks:mu
	owner *kernel.ThreadGroup
}

func (dev *tpuV4Device) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	hostPath := fmt.Sprintf("/dev/accel%d", dev.minor)
	hostFD, err := unix.Openat(-1, hostPath, int((opts.Flags&unix.O_ACCMODE)|unix.O_NOFOLLOW), 0)
	if err != nil {
		ctx.Warningf("accelDevice: failed to open host %s: %v", hostPath, err)
		return nil, err
	}
	fd := &tpuV4FD{
		hostFD: int32(hostFD),
		device: dev,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
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
	if vfs.MayWriteFileWithOpenFlags(opts.Flags) {
		dev.openWriteFDs++
	}
	if dev.owner == nil {
		t := kernel.TaskFromContext(ctx)
		if t == nil {
			return nil, linuxerr.ESRCH
		}
		dev.owner = t.ThreadGroup()
	}
	return &fd.vfsfd, nil
}

// CreateDevtmpfsFile creates a /dev/accel[0-9]+ device file.
func CreateDevtmpfsFile(ctx context.Context, dev *devtmpfs.Accessor, num uint32) error {
	return dev.CreateDeviceFile(ctx, fmt.Sprintf("accel%d", num), vfs.CharDevice, linux.ACCEL_MAJOR, num, 0666)
}

// RegisterTPUV4Device registers all devices implemented by this package in vfsObj.
func RegisterTPUV4Device(vfsObj *vfs.VirtualFilesystem, minor uint32, lite bool) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.ACCEL_MAJOR, minor, &tpuV4Device{
		lite:  lite,
		minor: minor,
	}, &vfs.RegisterDeviceOptions{
		GroupName: "accel",
	})
}
