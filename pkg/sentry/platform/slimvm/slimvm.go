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

// Package slimvm provides a slimvm-based implementation of the platform interface.
package slimvm

import (
	"fmt"
	"strconv"
	"sync"
	"syscall"

	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// SlimVM represents a lightweight VM context.
type SlimVM struct {
	// TODO: b/529809802 - Enable nogo. support CPU preemption detection.
	platform.NoCPUPreemptionDetection

	platform.UseHostProcessMemoryBarrier

	// TODO: b/529809802 - Follow commit 0b9bde06d0 to
	// add RSEQ support for SlimVM.
	platform.NoCPUNumbers

	// machine is the backing VM.
	machine *machine
}

var (
	globalOnce sync.Once
	globalErr  error
	slimvmFD   uintptr
	slimvmFile *fd.FD
)

// OpenDevice opens the SlimVM device at /dev/slimvm and returns the File.
func OpenDevice(devicePath string) (*fd.FD, error) {
	if devicePath == "" {
		devicePath = "/dev/slimvm"
	}
	f, err := fd.Open(devicePath, syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening %s: %v", devicePath, err)
	}
	return f, nil
}

// New returns a new SlimVM-based implementation of the platform interface.
func New(deviceFile *fd.FD, sandboxID string, applicationCores int) (*SlimVM, error) {
	slimvmFile = deviceFile
	slimvmFD = uintptr(slimvmFile.FD())

	// Ensure global initialization is done.
	globalOnce.Do(func() {
		updateGlobalOnce(int(slimvmFD))
	})
	if globalErr != nil {
		return nil, globalErr
	}

	// Parse sandbox ID for the host kernel module.
	sid, _ := strconv.ParseInt(sandboxID[:min(8, len(sandboxID))], 16, 64)

	// Create a VM context.
	machine, err := newMachine(sid, applicationCores)
	if err != nil {
		return nil, err
	}

	// All set.
	return &SlimVM{
		machine: machine,
	}, nil
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
func (*SlimVM) SupportsAddressSpaceIO() bool {
	return false
}

// CooperativelySchedulesAddressSpace implements platform.Platform.CooperativelySchedulesAddressSpace.
func (*SlimVM) CooperativelySchedulesAddressSpace() bool {
	return false
}

// MapUnit implements platform.Platform.MapUnit.
func (*SlimVM) MapUnit() uint64 {
	// We greedily creates PTEs in MapFile, so extremely large mappings can
	// be expensive. Not _that_ expensive since we allow super pages, but
	// even though can get out of hand if you're creating multi-terabyte
	// mappings. For this reason, we limit mappings to an arbitrary 16MB.
	return 16 << 20
}

// MinUserAddress returns the lowest available address.
func (*SlimVM) MinUserAddress() hostarch.Addr {
	return hostarch.PageSize
}

// MaxUserAddress returns the first address that may not be used.
func (*SlimVM) MaxUserAddress() hostarch.Addr {
	return hostarch.Addr(ring0.MaximumUserAddress)
}

// NewAddressSpace returns a new pagetable root.
func (k *SlimVM) NewAddressSpace() (platform.AddressSpace, error) {
	// Allocate page tables and install system mappings.
	pageTables := pagetables.NewWithUpper(newAllocator(), k.machine.upperSharedPageTables, ring0.KernelStartAddress)

	// Return the new address space.
	return &addressSpace{
		machine:    k.machine,
		pageTables: pageTables,
	}, nil
}

// NewContext returns an interruptible context.
func (k *SlimVM) NewContext(pkgcontext.Context) platform.Context {
	return &context{
		machine: k.machine,
	}
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount.
func (k *SlimVM) ConcurrencyCount() int {
	return k.machine.maxVCPUs
}

// HealthCheck implements platform.Platform.HealthCheck.
func (k *SlimVM) HealthCheck() {
	// TODO: b/529809802 - Implement.
	k.machine.mu.RLock()
	_ = struct{}{}
	k.machine.mu.RUnlock()
}

type constructor struct{}

func (*constructor) New(opts platform.Options) (platform.Platform, error) {
	return New(opts.DeviceFile, opts.SandboxID, opts.ApplicationCores)
}

func (*constructor) OpenDevice(devicePath string) (*fd.FD, error) {
	return OpenDevice(devicePath)
}

func (*constructor) Requirements() platform.Requirements {
	return platform.Requirements{}
}

func init() {
	platform.Register("slimvm", &constructor{})
}
