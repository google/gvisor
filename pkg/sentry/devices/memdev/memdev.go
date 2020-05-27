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

// Package memdev implements "mem" character devices, as implemented in Linux
// by drivers/char/mem.c and drivers/char/random.c.
package memdev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem) error {
	for minor, dev := range map[uint32]vfs.Device{
		nullDevMinor:    nullDevice{},
		zeroDevMinor:    zeroDevice{},
		fullDevMinor:    fullDevice{},
		randomDevMinor:  randomDevice{},
		urandomDevMinor: randomDevice{},
	} {
		if err := vfsObj.RegisterDevice(vfs.CharDevice, linux.MEM_MAJOR, minor, dev, &vfs.RegisterDeviceOptions{
			GroupName: "mem",
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
		nullDevMinor:    "null",
		zeroDevMinor:    "zero",
		fullDevMinor:    "full",
		randomDevMinor:  "random",
		urandomDevMinor: "urandom",
	} {
		if err := dev.CreateDeviceFile(ctx, name, vfs.CharDevice, linux.MEM_MAJOR, minor, 0666 /* mode */); err != nil {
			return err
		}
	}
	return nil
}
