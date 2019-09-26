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

// +build arm64

package kvm

import (
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

type vCPUArchState struct {
	// PCIDs is the set of PCIDs for this vCPU.
	//
	// This starts above fixedKernelPCID.
	PCIDs *pagetables.PCIDs
}

const (
	// fixedKernelPCID is a fixed kernel PCID used for the kernel page
	// tables. We must start allocating user PCIDs above this in order to
	// avoid any conflict (see below).
	fixedKernelPCID = 1

	// poolPCIDs is the number of PCIDs to record in the database. As this
	// grows, assignment can take longer, since it is a simple linear scan.
	// Beyond a relatively small number, there are likely few perform
	// benefits, since the TLB has likely long since lost any translations
	// from more than a few PCIDs past.
	poolPCIDs = 8
)

// Get all read-only physicalRegions.
func rdonlyRegionsForSetMem() (phyRegions []physicalRegion) {
	var rdonlyRegions []region

	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			return
		}

		if !vr.accessType.Write && vr.accessType.Read {
			rdonlyRegions = append(rdonlyRegions, vr.region)
		}
	})

	for _, r := range rdonlyRegions {
		physical, _, ok := translateToPhysical(r.virtual)
		if !ok {
			continue
		}

		phyRegions = append(phyRegions, physicalRegion{
			region: region{
				virtual: r.virtual,
				length:  r.length,
			},
			physical: physical,
		})
	}

	return phyRegions
}

// Get all available physicalRegions.
func availableRegionsForSetMem() (phyRegions []physicalRegion) {
	var excludeRegions []region
	applyVirtualRegions(func(vr virtualRegion) {
		if !vr.accessType.Write {
			excludeRegions = append(excludeRegions, vr.region)
		}
	})

	phyRegions = computePhysicalRegions(excludeRegions)

	return phyRegions
}

// dropPageTables drops cached page table entries.
func (m *machine) dropPageTables(pt *pagetables.PageTables) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear from all PCIDs.
	for _, c := range m.vCPUs {
		c.PCIDs.Drop(pt)
	}
}

// nonCanonical generates a canonical address return.
//
//go:nosplit
func nonCanonical(addr uint64, signal int32, info *arch.SignalInfo) (usermem.AccessType, error) {
	*info = arch.SignalInfo{
		Signo: signal,
		Code:  arch.SignalInfoKernel,
	}
	info.SetAddr(addr) // Include address.
	return usermem.NoAccess, platform.ErrContextSignal
}

// fault generates an appropriate fault return.
//
//go:nosplit
func (c *vCPU) fault(signal int32, info *arch.SignalInfo) (usermem.AccessType, error) {
	faultAddr := c.GetFaultAddr()
	code, user := c.ErrorCode()

	// Reset the pointed SignalInfo.
	*info = arch.SignalInfo{Signo: signal}
	info.SetAddr(uint64(faultAddr))

	read := true
	write := false
	execute := true

	ret := code & _ESR_ELx_FSC
	switch ret {
	case _ESR_SEGV_MAPERR_L0, _ESR_SEGV_MAPERR_L1, _ESR_SEGV_MAPERR_L2, _ESR_SEGV_MAPERR_L3:
		info.Code = 1 //SEGV_MAPERR
		read = false
		write = true
		execute = false
	case _ESR_SEGV_ACCERR_L1, _ESR_SEGV_ACCERR_L2, _ESR_SEGV_ACCERR_L3, _ESR_SEGV_PEMERR_L1, _ESR_SEGV_PEMERR_L2, _ESR_SEGV_PEMERR_L3:
		info.Code = 2 // SEGV_ACCERR.
		read = true
		write = false
		execute = false
	default:
		info.Code = 2
	}

	if !user {
		read = true
		write = false
		execute = true

	}
	accessType := usermem.AccessType{
		Read:    read,
		Write:   write,
		Execute: execute,
	}

	return accessType, platform.ErrContextSignal
}

// retryInGuest runs the given function in guest mode.
//
// If the function does not complete in guest mode (due to execution of a
// system call due to a GC stall, for example), then it will be retried. The
// given function must be idempotent as a result of the retry mechanism.
func (m *machine) retryInGuest(fn func()) {
	c := m.Get()
	defer m.Put(c)
	for {
		c.ClearErrorCode() // See below.
		bluepill(c)        // Force guest mode.
		fn()               // Execute the given function.
		_, user := c.ErrorCode()
		if user {
			// If user is set, then we haven't bailed back to host
			// mode via a kernel exception or system call. We
			// consider the full function to have executed in guest
			// mode and we can return.
			break
		}
	}
}
