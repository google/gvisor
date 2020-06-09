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

// Package miscdev implements "misc" character devices, as implemented in Linux
// by drivers/char/misc.c and fs/fuse/dev.c.
package miscdev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// miscDevMajor is the major device number for devices defined in this package.
const miscDevMajor = linux.MISC_MAJOR

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	for minor, dev := range map[uint32]vfs.Device{
		fuseDevMinor: fuseDevice{},
	} {
		if err := vfsObj.RegisterDevice(vfs.CharDevice, miscDevMajor, minor, dev, &vfs.RegisterDeviceOptions{
			GroupName: "misc",
		}); err != nil {
			return err
		}
	}
	return nil
}

// CreateDevtmpfsFiles creates device special files in dev representing all
// devices implemented by this package.
func CreateDevtmpfsFiles(ctx context.Context, dev *devtmpfs.Accessor) error {
	for minor, name := range map[uint32]string{
		fuseDevMinor: "fuse",
	} {
		if err := dev.CreateDeviceFile(ctx, name, vfs.CharDevice, miscDevMajor, minor, 0666 /* mode */); err != nil {
			return err
		}
	}
	return nil
}
