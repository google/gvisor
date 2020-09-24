// Copyright 2018 The gVisor Authors.
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
package device

import (
	"bytes"
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sync"
)

// Registry tracks all simple devices and related state on the system for
// save/restore.
//
// The set of devices across save/restore must remain consistent. That is, no
// devices may be created or removed on restore relative to the saved
// system. Practically, this means do not create new devices specifically as
// part of restore.
//
// +stateify savable
type Registry struct {
	// lastAnonDeviceMinor is the last minor device number used for an anonymous
	// device. Must be accessed atomically.
	//
	// +checkatomic
	lastAnonDeviceMinor uint64

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	devices map[ID]*Device
}

// SimpleDevices is the system-wide simple device registry. This is
// saved/restored by kernel.Kernel, but defined here to allow access without
// depending on the kernel package. See kernel.Kernel.deviceRegistry.
var SimpleDevices = newRegistry()

func newRegistry() *Registry {
	return &Registry{
		devices: make(map[ID]*Device),
	}
}

// newAnonID assigns a major and minor number to an anonymous device ID.
func (r *Registry) newAnonID() ID {
	return ID{
		// Anon devices always have a major number of 0.
		Major: 0,
		// Use the next minor number.
		Minor: atomic.AddUint64(&r.lastAnonDeviceMinor, 1),
	}
}

// newAnonDevice allocates a new anonymous device with a unique minor device
// number, and registers it with r.
func (r *Registry) newAnonDevice() *Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := &Device{
		ID: r.newAnonID(),
	}
	r.devices[d.ID] = d
	return d
}

// LoadFrom initializes the internal state of all devices in r from other. The
// set of devices in both registries must match. Devices may not be created or
// destroyed across save/restore.
func (r *Registry) LoadFrom(other *Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	other.mu.Lock()
	defer other.mu.Unlock()
	if len(r.devices) != len(other.devices) {
		panic(fmt.Sprintf("Devices were added or removed when restoring the registry:\nnew:\n%+v\nold:\n%+v", r.devices, other.devices))
	}
	for id, otherD := range other.devices {
		ourD, ok := r.devices[id]
		if !ok {
			panic(fmt.Sprintf("Device %+v could not be restored as it wasn't defined in the new registry", otherD))
		}
		ourD.loadFrom(otherD)
	}
	atomic.StoreUint64(&r.lastAnonDeviceMinor, atomic.LoadUint64(&other.lastAnonDeviceMinor))
}

// ID identifies a device.
//
// +stateify savable
type ID struct {
	Major uint64
	Minor uint64
}

// DeviceID formats a major and minor device number into a standard device number.
func (i *ID) DeviceID() uint64 {
	return uint64(linux.MakeDeviceID(uint16(i.Major), uint32(i.Minor)))
}

// NewAnonDevice creates a new anonymous device. Packages that require an anonymous
// device should initialize the device in a global variable in a file called device.go:
//
// var myDevice = device.NewAnonDevice()
func NewAnonDevice() *Device {
	return SimpleDevices.newAnonDevice()
}

// NewAnonMultiDevice creates a new multi-keyed anonymous device. Packages that require
// a multi-key anonymous device should initialize the device in a global variable in a
// file called device.go:
//
// var myDevice = device.NewAnonMultiDevice()
func NewAnonMultiDevice() *MultiDevice {
	return &MultiDevice{
		ID: SimpleDevices.newAnonID(),
	}
}

// Device is a simple virtual kernel device.
//
// +stateify savable
type Device struct {
	ID

	// last is the last generated inode.
	//
	// +checkatomic
	last uint64
}

// loadFrom initializes d from other. The IDs of both devices must match.
func (d *Device) loadFrom(other *Device) {
	if d.ID != other.ID {
		panic(fmt.Sprintf("Attempting to initialize a device %+v from %+v, but device IDs don't match", d, other))
	}
	atomic.StoreUint64(&d.last, atomic.LoadUint64(&other.last))
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
	m.mu.Lock()
	defer m.mu.Unlock()

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

	if val, exists := m.cache[key]; exists && val != value {
		return false
	}
	if k, exists := m.rcache[value]; exists && k != key {
		// Should never happen.
		panic(fmt.Sprintf("MultiDevice's caches are inconsistent, current: %+v, previous: %+v", key, k))
	}

	// Cache value at key.
	m.cache[key] = value

	// Prevent value from being used by new inode mappings.
	m.rcache[value] = key

	return true
}
