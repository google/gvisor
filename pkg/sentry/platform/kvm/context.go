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

package kvm

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/interrupt"
)

// context is an implementation of the platform context.
//
// This is a thin wrapper around the machine.
type context struct {
	// machine is the parent machine, and is immutable.
	machine *machine

	// info is the linux.SignalInfo cached for this context.
	info linux.SignalInfo

	// interrupt is the interrupt context.
	interrupt interrupt.Forwarder
}

// tryCPUIDError indicates that CPUID emulation should occur.
type tryCPUIDError struct{}

// Error implements error.Error.
func (tryCPUIDError) Error() string { return "cpuid emulation failed" }

// Switch runs the provided context in the given address space.
func (c *context) Switch(ctx pkgcontext.Context, mm platform.MemoryManager, ac *arch.Context64, _ int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	as := mm.AddressSpace()
	localAS := as.(*addressSpace)

restart:
	// Grab a vCPU.
	cpu := c.machine.Get()

	// Enable interrupts (i.e. calls to vCPU.Notify).
	if !c.interrupt.Enable(cpu) {
		c.machine.Put(cpu) // Already preempted.
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}

	// Set the active address space.
	//
	// This must be done prior to the call to Touch below. If the address
	// space is invalidated between this line and the call below, we will
	// flag on entry anyways. When the active address space below is
	// cleared, it indicates that we don't need an explicit interrupt and
	// that the flush can occur naturally on the next user entry.
	cpu.active.set(localAS)

	// Prepare switch options.
	switchOpts := ring0.SwitchOpts{
		Registers:          &ac.StateData().Regs,
		FloatingPointState: ac.FloatingPointData(),
		PageTables:         localAS.pageTables,
		Flush:              localAS.Touch(cpu),
		FullRestore:        ac.FullRestore(),
	}

	// Take the blue pill.
	at, err := cpu.SwitchToUser(switchOpts, &c.info)

	// Clear the address space.
	cpu.active.set(nil)

	// Increment the number of user exits.
	cpu.userExits.Add(1)
	userExitCounter.Increment()

	// Release resources.
	c.machine.Put(cpu)

	// All done.
	c.interrupt.Disable()

	if err != nil {
		if _, ok := err.(tryCPUIDError); ok {
			// Does emulation work for the CPUID?
			//
			// We have to put the current vCPU, because
			// TryCPUIDEmulate needs to read a user memory and it
			// has to lock mm.activeMu for that, but it can race
			// with as.invalidate that bonce all vcpu-s to gr0 and
			// is called under mm.activeMu too.
			if platform.TryCPUIDEmulate(ctx, mm, ac) {
				goto restart
			}
			// If not a valid CPUID, then the signal should be
			// delivered as is and the information is filled.
			err = platform.ErrContextSignal
		}
	}
	return &c.info, at, err
}

// Interrupt interrupts the running context.
func (c *context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// Release implements platform.Context.Release().
func (c *context) Release() {}

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *context) FullStateChanged() {}

// PullFullState implements platform.Context.PullFullState.
func (c *context) PullFullState(as platform.AddressSpace, ac *arch.Context64) {}

// PrepareSleep implements platform.Context.platform.Context.
func (*context) PrepareSleep() {}
