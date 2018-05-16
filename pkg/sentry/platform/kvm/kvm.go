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

// Package kvm provides a kvm-based implementation of the platform interface.
package kvm

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/filemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// KVM represents a lightweight VM context.
type KVM struct {
	platform.NoCPUPreemptionDetection

	// filemem is our memory source.
	*filemem.FileMem

	// machine is the backing VM.
	machine *machine
}

var (
	globalOnce sync.Once
	globalErr  error
)

// New returns a new KVM-based implementation of the platform interface.
func New() (*KVM, error) {
	// Allocate physical memory for the vCPUs.
	fm, err := filemem.New("kvm-memory")
	if err != nil {
		return nil, err
	}

	// Try opening KVM.
	fd, err := syscall.Open("/dev/kvm", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening /dev/kvm: %v", err)
	}
	defer syscall.Close(fd)

	// Ensure global initialization is done.
	globalOnce.Do(func() {
		physicalInit()
		globalErr = updateSystemValues(fd)
		ring0.Init(cpuid.HostFeatureSet())
	})
	if globalErr != nil {
		return nil, err
	}

	// Create a new VM fd.
	vm, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(fd), _KVM_CREATE_VM, 0)
	if errno != 0 {
		return nil, fmt.Errorf("creating VM: %v", errno)
	}

	// Create a VM context.
	machine, err := newMachine(int(vm), runtime.NumCPU())
	if err != nil {
		return nil, err
	}

	// All set.
	return &KVM{
		FileMem: fm,
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
	pageTables := k.machine.kernel.PageTables.New()
	applyPhysicalRegions(func(pr physicalRegion) bool {
		// Map the kernel in the upper half.
		kernelVirtual := usermem.Addr(ring0.KernelStartAddress | pr.virtual)
		pageTables.Map(kernelVirtual, pr.length, false /* kernel */, usermem.AnyAccess, pr.physical)
		return true // Keep iterating.
	})

	// Return the new address space.
	return &addressSpace{
		filemem:    k.FileMem,
		machine:    k.machine,
		pageTables: pageTables,
		dirtySet:   makeDirtySet(len(k.machine.vCPUs)),
	}, nil, nil
}

// NewContext returns an interruptible context.
func (k *KVM) NewContext() platform.Context {
	return &context{
		machine: k.machine,
	}
}

// Memory returns the platform memory used to do allocations.
func (k *KVM) Memory() platform.Memory {
	return k.FileMem
}
