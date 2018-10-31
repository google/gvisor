// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/interrupt"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// context is an implementation of the platform context.
//
// This is a thin wrapper around the machine.
type context struct {
	// machine is the parent machine, and is immutable.
	machine *machine

	// info is the arch.SignalInfo cached for this context.
	info arch.SignalInfo

	// interrupt is the interrupt context.
	interrupt interrupt.Forwarder
}

// Switch runs the provided context in the given address space.
func (c *context) Switch(as platform.AddressSpace, ac arch.Context, _ int32) (*arch.SignalInfo, usermem.AccessType, error) {
	localAS := as.(*addressSpace)

	// Grab a vCPU.
	cpu := c.machine.Get()

	// Enable interrupts (i.e. calls to vCPU.Notify).
	if !c.interrupt.Enable(cpu) {
		c.machine.Put(cpu) // Already preempted.
		return nil, usermem.NoAccess, platform.ErrContextInterrupt
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
		FloatingPointState: (*byte)(ac.FloatingPointData()),
		PageTables:         localAS.pageTables,
		Flush:              localAS.Touch(cpu),
		FullRestore:        ac.FullRestore(),
	}

	// Take the blue pill.
	at, err := cpu.SwitchToUser(switchOpts, &c.info)

	// Clear the address space.
	cpu.active.set(nil)

	// Release resources.
	c.machine.Put(cpu)

	// All done.
	c.interrupt.Disable()
	return &c.info, at, err
}

// Interrupt interrupts the running context.
func (c *context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}
