// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// DeviceKind indicates whether a device is a block or character device.
//
// +stateify savable
type DeviceKind uint32

const (
	// BlockDevice indicates a block device.
	BlockDevice DeviceKind = iota

	// CharDevice indicates a character device.
	CharDevice
)

// String implements fmt.Stringer.String.
func (kind DeviceKind) String() string {
	switch kind {
	case BlockDevice:
		return "block"
	case CharDevice:
		return "character"
	default:
		return fmt.Sprintf("invalid device kind %d", kind)
	}
}

// +stateify savable
type devTuple struct {
	kind  DeviceKind
	major uint32
	minor uint32
}

// A Device backs device special files.
type Device interface {
	// Open returns a FileDescription representing this device.
	Open(ctx context.Context, mnt *Mount, d *Dentry, opts OpenOptions) (*FileDescription, error)
}

// +stateify savable
type registeredDevice struct {
	dev  Device
	opts RegisterDeviceOptions
}

// RegisterDeviceOptions contains options to
// VirtualFilesystem.RegisterDevice().
//
// +stateify savable
type RegisterDeviceOptions struct {
	// GroupName is the name shown for this device registration in
	// /proc/devices. If GroupName is empty, this registration will not be
	// shown in /proc/devices.
	GroupName string
}

// RegisterDevice registers the given Device in vfs with the given major and
// minor device numbers.
func (vfs *VirtualFilesystem) RegisterDevice(kind DeviceKind, major, minor uint32, dev Device, opts *RegisterDeviceOptions) error {
	tup := devTuple{kind, major, minor}
	vfs.devicesMu.Lock()
	defer vfs.devicesMu.Unlock()
	if existing, ok := vfs.devices[tup]; ok {
		return fmt.Errorf("%s device number (%d, %d) is already registered to device type %T", kind, major, minor, existing.dev)
	}
	vfs.devices[tup] = &registeredDevice{
		dev:  dev,
		opts: *opts,
	}
	return nil
}

// OpenDeviceSpecialFile returns a FileDescription representing the given
// device.
func (vfs *VirtualFilesystem) OpenDeviceSpecialFile(ctx context.Context, mnt *Mount, d *Dentry, kind DeviceKind, major, minor uint32, opts *OpenOptions) (*FileDescription, error) {
	tup := devTuple{kind, major, minor}
	vfs.devicesMu.RLock()
	defer vfs.devicesMu.RUnlock()
	rd, ok := vfs.devices[tup]
	if !ok {
		return nil, linuxerr.ENXIO
	}
	return rd.dev.Open(ctx, mnt, d, *opts)
}

// GetDynamicCharDevMajor allocates and returns an unused major device number
// for a character device or set of character devices.
func (vfs *VirtualFilesystem) GetDynamicCharDevMajor() (uint32, error) {
	vfs.dynCharDevMajorMu.Lock()
	defer vfs.dynCharDevMajorMu.Unlock()
	// Compare Linux's fs/char_dev.c:find_dynamic_major().
	for major := uint32(254); major >= 234; major-- {
		if _, ok := vfs.dynCharDevMajorUsed[major]; !ok {
			vfs.dynCharDevMajorUsed[major] = struct{}{}
			return major, nil
		}
	}
	for major := uint32(511); major >= 384; major-- {
		if _, ok := vfs.dynCharDevMajorUsed[major]; !ok {
			vfs.dynCharDevMajorUsed[major] = struct{}{}
			return major, nil
		}
	}
	return 0, linuxerr.EBUSY
}

// PutDynamicCharDevMajor deallocates a major device number returned by a
// previous call to GetDynamicCharDevMajor.
func (vfs *VirtualFilesystem) PutDynamicCharDevMajor(major uint32) {
	vfs.dynCharDevMajorMu.Lock()
	defer vfs.dynCharDevMajorMu.Unlock()
	delete(vfs.dynCharDevMajorUsed, major)
}

// GetAnonBlockDevMinor allocates and returns an unused minor device number for
// an "anonymous" block device with major number UNNAMED_MAJOR.
func (vfs *VirtualFilesystem) GetAnonBlockDevMinor() (uint32, error) {
	vfs.anonBlockDevMinorMu.Lock()
	defer vfs.anonBlockDevMinorMu.Unlock()
	minor := vfs.anonBlockDevMinorNext
	const maxDevMinor = (1 << 20) - 1
	for minor < maxDevMinor {
		if _, ok := vfs.anonBlockDevMinor[minor]; !ok {
			vfs.anonBlockDevMinor[minor] = struct{}{}
			vfs.anonBlockDevMinorNext = minor + 1
			return minor, nil
		}
		minor++
	}
	return 0, linuxerr.EMFILE
}

// PutAnonBlockDevMinor deallocates a minor device number returned by a
// previous call to GetAnonBlockDevMinor.
func (vfs *VirtualFilesystem) PutAnonBlockDevMinor(minor uint32) {
	vfs.anonBlockDevMinorMu.Lock()
	defer vfs.anonBlockDevMinorMu.Unlock()
	delete(vfs.anonBlockDevMinor, minor)
	if minor < vfs.anonBlockDevMinorNext {
		vfs.anonBlockDevMinorNext = minor
	}
}
