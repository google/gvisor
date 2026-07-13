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

// Package rdmaproxy implements a proxy for RDMA drivers
package rdmaproxy

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// enabled records whether RDMA device proxying is in use for this sentry.
// Used by pkg/sentry/fsimpl/proc/rdmaproxy.go to decide whether to expose a
// working /proc/bus/pci/devices: RDMA userspace tools built against libpci
// (e.g. perftest) call into pciutils, which fatally exits if no PCI access
// method succeeds at all; an empty /proc/bus/pci/devices is a valid,
// zero-device outcome that avoids that exit.
//
// This must be set by SetEnabled before any container's VFS is set up, since
// procfs is built from a static content map at mount time; by the time
// RegisterRDMADevice runs, device nodes are already being created after
// mounts, so it is too late for this purpose.
var enabled atomicbitops.Bool

// SetEnabled records whether RDMA device proxying is in use for this sentry.
func SetEnabled(v bool) {
	enabled.Store(v)
}

// Enabled returns whether RDMA device proxying is in use for this sentry.
func Enabled() bool {
	return enabled.Load()
}

const (
	// See drivers/infiniband/core/uverbs_main.c
	rdmaDevMajor        = 231
	rdmaDeviceGroupName = "infiniband_verbs"
)

type rdmaproxy struct{}

// rdmaDevice implements vfs.Device for /dev/infiniband/uverbs*.
//
// +stateify savable
type rdmaDevice struct {
	mu sync.Mutex `state:"nosave"`

	// rdmap is state of the rdma proxy
	rdmap *rdmaproxy
	// minor is the device minor number.
	minor uint32
	// num is the number of the device in the dev filesystem (e.g /dev/infiniband/uverbs0).
	num uint32
	// useDevGofer indicates whether to use device gofer to open the TPU device.
	useDevGofer bool
}

// Open implements vfs.Device.Open.
func (dev *rdmaDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devPath := fmt.Sprintf("infiniband/uverbs%d", dev.num)
	hostFD, err := openHostFD(ctx, devPath, opts.Flags, dev.useDevGofer)
	if err != nil {
		return nil, err
	}

	fd := &rdmaFD{
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
	fd.memmapFile.SetFD(hostFD)
	return &fd.vfsfd, nil
}

// RegisterRDMADevice registers all devices implemented by this package in vfsObj.
func RegisterRDMADevice(vfsObj *vfs.VirtualFilesystem, minor, deviceNum uint32, useDevGofer bool) error {
	recordUverbsDevice(deviceNum, minor)
	if vfsObj.IsDeviceRegistered(vfs.CharDevice, rdmaDevMajor, minor) {
		return nil
	}
	return vfsObj.RegisterDevice(vfs.CharDevice, rdmaDevMajor, minor, &rdmaDevice{
		minor:       minor,
		num:         deviceNum,
		useDevGofer: useDevGofer,
	}, &vfs.RegisterDeviceOptions{
		GroupName: rdmaDeviceGroupName,
		Pathname:  fmt.Sprintf("infiniband/uverbs%d", deviceNum),
		FilePerms: 0666,
	})
}

func openHostFD(ctx context.Context, devName string, flags uint32, useDevGofer bool) (int, error) {
	if useDevGofer {
		client := devutil.GoferClientFromContext(ctx)
		if client == nil {
			log.Warningf("rdmaproxy: devutil.CtxDevGoferClient is not set")
			return -1, linuxerr.ENOENT
		}
		return client.OpenAt(ctx, devName, flags)
	}
	devPath := filepath.Join("/", "dev", devName)
	openFlags := int(flags&unix.O_ACCMODE | unix.O_NOFOLLOW)
	return unix.Openat(-1, devPath, openFlags, 0)
}
