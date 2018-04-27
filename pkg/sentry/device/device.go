// Copyright 2018 Google Inc.
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

// Package device defines reserved virtual kernel devices and structures
// for managing them.
//
// Saving and restoring devices is not necessary if the devices are initialized
// as package global variables. Package initialization happens in a single goroutine
// and in a deterministic order, so minor device numbers will be assigned in the
// same order as packages are loaded.
package device

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// ID identifies a device.
type ID struct {
	Major uint64
	Minor uint64
}

// DeviceID formats a major and minor device number into a standard device number.
func (i *ID) DeviceID() uint64 {
	return uint64(linux.MakeDeviceID(uint16(i.Major), uint32(i.Minor)))
}

// nextAnonDeviceMinor is the next minor number for a new anonymous device.
// Must be accessed atomically.
var nextAnonDeviceMinor uint64

// NewAnonDevice creates a new anonymous device. Packages that require an anonymous
// device should initialize the device in a global variable in a file called device.go:
//
// var myDevice = device.NewAnonDevice()
func NewAnonDevice() *Device {
	return &Device{
		ID: newAnonID(),
	}
}

// NewAnonMultiDevice creates a new multi-keyed anonymous device. Packages that require
// a multi-key anonymous device should initialize the device in a global variable in a
// file called device.go:
//
// var myDevice = device.NewAnonMultiDevice()
func NewAnonMultiDevice() *MultiDevice {
	return &MultiDevice{
		ID: newAnonID(),
	}
}

// newAnonID assigns a major and minor number to an anonymous device ID.
func newAnonID() ID {
	return ID{
		// Anon devices always have a major number of 0.
		Major: 0,
		// Use the next minor number.
		Minor: atomic.AddUint64(&nextAnonDeviceMinor, 1),
	}
}

// Device is a simple virtual kernel device.
type Device struct {
	ID

	// last is the last generated inode.
	last uint64
}

// NextIno generates a new inode number
func (d *Device) NextIno() uint64 {
	return atomic.AddUint64(&d.last, 1)
}

// MultiDeviceKey provides a hashable key for a MultiDevice. The key consists
// of a raw device and inode for a resource, which must consistently identify
// the unique resource.  It may optionally include a secondary device if
// appropriate.
//
// Note that using the path is not enough, because filesystems may rename a file
// to a different backing resource, at which point the path points to a different
// entity.  Using only the inode is also not enough because the inode is assumed
// to be unique only within the device on which the resource exists.
type MultiDeviceKey struct {
	Device          uint64
	SecondaryDevice string
	Inode           uint64
}

// String stringifies the key.
func (m MultiDeviceKey) String() string {
	return fmt.Sprintf("key{device: %d, sdevice: %s, inode: %d}", m.Device, m.SecondaryDevice, m.Inode)
}

// MultiDevice allows for remapping resources that come from a variety of raw
// devices into a single device.  The device ID should be one of the static
// Device IDs above and cannot be reused.
type MultiDevice struct {
	ID

	mu     sync.Mutex
	last   uint64
	cache  map[MultiDeviceKey]uint64
	rcache map[uint64]MultiDeviceKey
}

// String stringifies MultiDevice.
func (m *MultiDevice) String() string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("cache{")
	for k, v := range m.cache {
		buf.WriteString(fmt.Sprintf("%s -> %d, ", k, v))
	}
	buf.WriteString("}")
	return buf.String()
}

// Map maps a raw device and inode into the inode space of MultiDevice,
// returning a virtualized inode.  Raw devices and inodes can be reused;
// in this case, the same virtual inode will be returned.
func (m *MultiDevice) Map(key MultiDeviceKey) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cache == nil {
		m.cache = make(map[MultiDeviceKey]uint64)
		m.rcache = make(map[uint64]MultiDeviceKey)
	}

	id, ok := m.cache[key]
	if ok {
		return id
	}
	// Step over reserved entries that may have been loaded.
	idx := m.last + 1
	for {
		if _, ok := m.rcache[idx]; !ok {
			break
		}
		idx++
	}
	// We found a non-reserved entry, use it.
	m.last = idx
	m.cache[key] = m.last
	m.rcache[m.last] = key
	return m.last
}

// Load loads a raw device and inode into MultiDevice inode mappings
// with value as the virtual inode.
//
// By design, inodes start from 1 and continue until max uint64.  This means
// that the zero value, which is often the uninitialized value, can be rejected
// as invalid.
func (m *MultiDevice) Load(key MultiDeviceKey, value uint64) bool {
	// Reject the uninitialized value; see comment above.
	if value == 0 {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cache == nil {
		m.cache = make(map[MultiDeviceKey]uint64)
		m.rcache = make(map[uint64]MultiDeviceKey)
	}

	// Cache value at key.
	m.cache[key] = value

	// Prevent value from being used by new inode mappings.
	m.rcache[value] = key

	return true
}
