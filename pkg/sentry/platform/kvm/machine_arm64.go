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

//go:build arm64
// +build arm64

package kvm

import (
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

type machineArchState struct {
	//initialvCPUs is the machine vCPUs which has initialized but not used
	initialvCPUs map[int]*vCPU
}

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
	poolPCIDs = 128
)

func (m *machine) mapUpperHalf(pageTable *pagetables.PageTables) {
	applyPhysicalRegions(func(pr physicalRegion) bool {
		pageTable.Map(
			hostarch.Addr(ring0.KernelStartAddress|pr.virtual),
			pr.length,
			pagetables.MapOpts{AccessType: hostarch.AnyAccess, Global: true},
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

// archPhysicalRegions fills readOnlyGuestRegions and allocates separate
// physical regions form them.
func archPhysicalRegions(physicalRegions []physicalRegion) []physicalRegion {
	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			return // skip region.
		}
		if !vr.accessType.Write {
			readOnlyGuestRegions = append(readOnlyGuestRegions, vr.region)
		}
	})

	rdRegions := readOnlyGuestRegions[:]

	// Add an unreachable region.
	rdRegions = append(rdRegions, region{
		virtual: 0xffffffffffffffff,
		length:  0,
	})

	var regions []physicalRegion
	addValidRegion := func(r *physicalRegion, virtual, length uintptr) {
		if length == 0 {
			return
		}
		regions = append(regions, physicalRegion{
			region: region{
				virtual: virtual,
				length:  length,
			},
			physical: r.physical + (virtual - r.virtual),
		})
	}
	i := 0
	for _, pr := range physicalRegions {
		start := pr.virtual
		end := pr.virtual + pr.length
		for start < end {
			rdRegion := rdRegions[i]
			rdStart := rdRegion.virtual
			rdEnd := rdRegion.virtual + rdRegion.length
			if rdEnd <= start {
				i++
				continue
			}
			if rdStart > start {
				newEnd := rdStart
				if end < rdStart {
					newEnd = end
				}
				addValidRegion(&pr, start, newEnd-start)
				start = rdStart
				continue
			}
			if rdEnd < end {
				addValidRegion(&pr, start, rdEnd-start)
				start = rdEnd
				continue
			}
			addValidRegion(&pr, start, end-start)
			start = end
		}
	}

	return regions
}

// Get all available physicalRegions.
func availableRegionsForSetMem() []physicalRegion {
	var excludedRegions []region
	applyVirtualRegions(func(vr virtualRegion) {
		if !vr.accessType.Write {
			excludedRegions = append(excludedRegions, vr.region)
		}
	})

	// Add an unreachable region.
	excludedRegions = append(excludedRegions, region{
		virtual: 0xffffffffffffffff,
		length:  0,
	})

	var regions []physicalRegion
	addValidRegion := func(r *physicalRegion, virtual, length uintptr) {
		if length == 0 {
			return
		}
		regions = append(regions, physicalRegion{
			region: region{
				virtual: virtual,
				length:  length,
			},
			physical: r.physical + (virtual - r.virtual),
		})
	}
	i := 0
	for _, pr := range physicalRegions {
		start := pr.virtual
		end := pr.virtual + pr.length
		for start < end {
			er := excludedRegions[i]
			excludeEnd := er.virtual + er.length
			excludeStart := er.virtual
			if excludeEnd < start {
				i++
				continue
			}
			if excludeStart < start {
				start = excludeEnd
				i++
				continue
			}
			rend := excludeStart
			if rend > end {
				rend = end
			}
			addValidRegion(&pr, start, rend-start)
			start = excludeEnd
		}
	}

	return regions
}

// nonCanonical generates a canonical address return.
//
//go:nosplit
func nonCanonical(addr uint64, signal int32, info *linux.SignalInfo) (hostarch.AccessType, error) {
	*info = linux.SignalInfo{
		Signo: signal,
		Code:  linux.SI_KERNEL,
	}
	info.SetAddr(addr) // Include address.
	return hostarch.NoAccess, platform.ErrContextSignal
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
func (c *vCPU) fault(signal int32, info *linux.SignalInfo) (hostarch.AccessType, error) {
	bluepill(c) // Probably no-op, but may not be.
	faultAddr := c.GetFaultAddr()
	code, user := c.ErrorCode()
	if !user {
		// The last fault serviced by this CPU was not a user
		// fault, so we can't reliably trust the faultAddr or
		// the code provided here. We need to re-execute.
		return hostarch.NoAccess, platform.ErrContextInterrupt
	}

	// Reset the pointed SignalInfo.
	*info = linux.SignalInfo{Signo: signal}
	info.SetAddr(uint64(faultAddr))
	accessType := hostarch.AccessType{}
	if signal == int32(unix.SIGSEGV) {
		accessType = hostarch.AccessType{
			Read:    !isWriteFault(uint64(code)),
			Write:   isWriteFault(uint64(code)),
			Execute: isInstructionAbort(uint64(code)),
		}
	}

	ret := code & _ESR_ELx_FSC
	switch ret {
	case _ESR_SEGV_MAPERR_L0, _ESR_SEGV_MAPERR_L1, _ESR_SEGV_MAPERR_L2, _ESR_SEGV_MAPERR_L3:
		info.Code = 1 //SEGV_MAPERR
	case _ESR_SEGV_ACCERR_L1, _ESR_SEGV_ACCERR_L2, _ESR_SEGV_ACCERR_L3, _ESR_SEGV_PEMERR_L1, _ESR_SEGV_PEMERR_L2, _ESR_SEGV_PEMERR_L3:
		info.Code = 2 // SEGV_ACCERR.
	default:
		info.Code = 2
	}

	return accessType, platform.ErrContextSignal
}

// getMaxVCPU get max vCPU number
func (m *machine) getMaxVCPU() {
	rmaxVCPUs := runtime.NumCPU()
	smaxVCPUs, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), _KVM_CHECK_EXTENSION, _KVM_CAP_MAX_VCPUS)
	// compare the max vcpu number from runtime and syscall, use smaller one.
	if errno != 0 {
		m.maxVCPUs = rmaxVCPUs
	} else {
		if rmaxVCPUs < int(smaxVCPUs) {
			m.maxVCPUs = rmaxVCPUs
		} else {
			m.maxVCPUs = int(smaxVCPUs)
		}
	}
}

// getNewVCPU() scan for an available vCPU from initialvCPUs
func (m *machine) getNewVCPU() *vCPU {
	for CID, c := range m.initialvCPUs {
		if atomic.CompareAndSwapUint32(&c.state, vCPUReady, vCPUUser) {
			delete(m.initialvCPUs, CID)
			return c
		}
	}
	return nil
}
