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

// Package kvm provides a kvm-based implementation of the platform interface.
package kvm

import (
	"fmt"
	"os"
	"syscall"

	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// userMemoryRegion is a region of physical memory.
//
// This mirrors kvm_memory_region.
type userMemoryRegion struct {
	slot          uint32
	flags         uint32
	guestPhysAddr uint64
	memorySize    uint64
	userspaceAddr uint64
}

// runData is the run structure. This may be mapped for synchronous register
// access (although that doesn't appear to be supported by my kernel at least).
//
// This mirrors kvm_run.
type runData struct {
	requestInterruptWindow uint8
	_                      [7]uint8

	exitReason                 uint32
	readyForInterruptInjection uint8
	ifFlag                     uint8
	_                          [2]uint8

	cr8      uint64
	apicBase uint64

	// This is the union data for exits. Interpretation depends entirely on
	// the exitReason above (see vCPU code for more information).
	data [32]uint64
}

// KVM represents a lightweight VM context.
type KVM struct {
	platform.NoCPUPreemptionDetection

	// machine is the backing VM.
	machine *machine
}

var (
	globalOnce sync.Once
	globalErr  error
)

// OpenDevice opens the KVM device at /dev/kvm and returns the File.
func OpenDevice() (*os.File, error) {
	f, err := os.OpenFile("/dev/kvm", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening /dev/kvm: %v", err)
	}
	return f, nil
}

// New returns a new KVM-based implementation of the platform interface.
func New(deviceFile *os.File) (*KVM, error) {
	fd := deviceFile.Fd()

	// Ensure global initialization is done.
	globalOnce.Do(func() {
		globalErr = updateGlobalOnce(int(fd))
	})
	if globalErr != nil {
		return nil, globalErr
	}

	// Create a new VM fd.
	var (
		vm    uintptr
		errno syscall.Errno
	)
	for {
		vm, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, _KVM_CREATE_VM, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return nil, fmt.Errorf("creating VM: %v", errno)
		}
		break
	}
	// We are done with the device file.
	deviceFile.Close()

	// Create a VM context.
	machine, err := newMachine(int(vm))
	if err != nil {
		return nil, err
	}

	// All set.
	return &KVM{
		machine: machine,
	}, nil
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
func (*KVM) SupportsAddressSpaceIO() bool {
	return false
}

// CooperativelySchedulesAddressSpace implements platform.Platform.CooperativelySchedulesAddressSpace.
func (*KVM) CooperativelySchedulesAddressSpace() bool {
	return false
}

// MapUnit implements platform.Platform.MapUnit.
func (*KVM) MapUnit() uint64 {
	// We greedily creates PTEs in MapFile, so extremely large mappings can
	// be expensive. Not _that_ expensive since we allow super pages, but
	// even though can get out of hand if you're creating multi-terabyte
	// mappings. For this reason, we limit mappings to an arbitrary 16MB.
	return 16 << 20
}

// MinUserAddress returns the lowest available address.
func (*KVM) MinUserAddress() usermem.Addr {
	return usermem.PageSize
}

// MaxUserAddress returns the first address that may not be used.
func (*KVM) MaxUserAddress() usermem.Addr {
	return usermem.Addr(ring0.MaximumUserAddress)
}

// NewAddressSpace returns a new pagetable root.
func (k *KVM) NewAddressSpace(_ interface{}) (platform.AddressSpace, <-chan struct{}, error) {
	// Allocate page tables and install system mappings.
	pageTables := pagetables.New(newAllocator())
	k.machine.mapUpperHalf(pageTables)

	// Return the new address space.
	return &addressSpace{
		machine:    k.machine,
		pageTables: pageTables,
		dirtySet:   k.machine.newDirtySet(),
	}, nil, nil
}

// NewContext returns an interruptible context.
func (k *KVM) NewContext() platform.Context {
	return &context{
		machine: k.machine,
	}
}

type constructor struct{}

func (*constructor) New(f *os.File) (platform.Platform, error) {
	return New(f)
}

func (*constructor) OpenDevice() (*os.File, error) {
	return OpenDevice()
}

// Flags implements platform.Constructor.Flags().
func (*constructor) Requirements() platform.Requirements {
	return platform.Requirements{}
}

func init() {
	platform.Register("kvm", &constructor{})
}
