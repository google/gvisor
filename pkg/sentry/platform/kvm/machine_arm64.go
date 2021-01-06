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
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/usermem"
)

type vCPUArchState struct {
	// PCIDs is the set of PCIDs for this vCPU.
	//
	// This starts above fixedKernelPCID.
	PCIDs *pagetables.PCIDs

	// floatingPointState is the floating point state buffer used in guest
	// to host transitions. See usage in bluepill_arm64.go.
	floatingPointState *arch.FloatingPointData
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

func (m *machine) mapUpperHalf(pageTable *pagetables.PageTables) {
	applyPhysicalRegions(func(pr physicalRegion) bool {
		pageTable.Map(
			usermem.Addr(ring0.KernelStartAddress|pr.virtual),
			pr.length,
			pagetables.MapOpts{AccessType: usermem.AnyAccess, Global: true},
			pr.physical)

		return true // Keep iterating.
	})
}

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

		// TODO(gvisor.dev/issue/2686): PROT_NONE should be specially treated.
		// Workaround: treated as rdonly temporarily.
		if !vr.accessType.Write && !vr.accessType.Read && !vr.accessType.Execute {
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

// isInstructionAbort returns true if it is an instruction abort.
//
//go:nosplit
func isInstructionAbort(code uint64) bool {
	value := (code & _ESR_ELx_EC_MASK) >> _ESR_ELx_EC_SHIFT
	return value == _ESR_ELx_EC_IABT_LOW
}

// isWriteFault returns whether it is a write fault.
//
//go:nosplit
func isWriteFault(code uint64) bool {
	if isInstructionAbort(code) {
		return false
	}

	return (code & _ESR_ELx_WNR) != 0
}

// fault generates an appropriate fault return.
//
//go:nosplit
func (c *vCPU) fault(signal int32, info *arch.SignalInfo) (usermem.AccessType, error) {
	bluepill(c) // Probably no-op, but may not be.
	faultAddr := c.GetFaultAddr()
	code, user := c.ErrorCode()

	if !user {
		// The last fault serviced by this CPU was not a user
		// fault, so we can't reliably trust the faultAddr or
		// the code provided here. We need to re-execute.
		return usermem.NoAccess, platform.ErrContextInterrupt
	}

	// Reset the pointed SignalInfo.
	*info = arch.SignalInfo{Signo: signal}
	info.SetAddr(uint64(faultAddr))

	ret := code & _ESR_ELx_FSC
	switch ret {
	case _ESR_SEGV_MAPERR_L0, _ESR_SEGV_MAPERR_L1, _ESR_SEGV_MAPERR_L2, _ESR_SEGV_MAPERR_L3:
		info.Code = 1 //SEGV_MAPERR
	case _ESR_SEGV_ACCERR_L1, _ESR_SEGV_ACCERR_L2, _ESR_SEGV_ACCERR_L3, _ESR_SEGV_PEMERR_L1, _ESR_SEGV_PEMERR_L2, _ESR_SEGV_PEMERR_L3:
		info.Code = 2 // SEGV_ACCERR.
	default:
		info.Code = 2
	}

	accessType := usermem.AccessType{
		Read:    !isWriteFault(uint64(code)),
		Write:   isWriteFault(uint64(code)),
		Execute: isInstructionAbort(uint64(code)),
	}

	return accessType, platform.ErrContextSignal
}
