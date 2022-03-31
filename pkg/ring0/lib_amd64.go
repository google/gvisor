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

//go:build amd64
// +build amd64

package ring0

import (
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// writeFS sets the FS base address (selects one of wrfsbase or wrfsmsr).
func writeFS(addr uintptr)

// wrfsbase writes to the GS base address.
func wrfsbase(addr uintptr)

// wrfsmsr writes to the GS_BASE MSR.
func wrfsmsr(addr uintptr)

// writeGS sets the GS address (selects one of wrgsbase or wrgsmsr).
func writeGS(addr uintptr)

// wrgsbase writes to the GS base address.
func wrgsbase(addr uintptr)

// wrgsmsr writes to the GS_BASE MSR.
func wrgsmsr(addr uintptr)

// stmxcsr reads the MXCSR control and status register.
func stmxcsr(addr *uint32)

// ldmxcsr writes to the MXCSR control and status register.
func ldmxcsr(addr *uint32)

// readCR2 reads the current CR2 value.
func readCR2() uintptr

// fninit initializes the floating point unit.
func fninit()

// xsetbv writes to an extended control register.
func xsetbv(reg, value uintptr)

// xgetbv reads an extended control register.
func xgetbv(reg uintptr) uintptr

// wrmsr reads to the given MSR.
func wrmsr(reg, value uintptr)

// rdmsr reads the given MSR.
func rdmsr(reg uintptr) uintptr

// Mostly-constants set by Init.
var (
	hasSMEP       bool
	hasSMAP       bool
	hasPCID       bool
	hasXSAVEOPT   bool
	hasXSAVE      bool
	hasFSGSBASE   bool
	validXCR0Mask uintptr
	localXCR0     uintptr
)

// Init sets function pointers based on architectural features.
//
// This must be called prior to using ring0. By default, it will be called by
// the init() function. However, it may be called at another time with a
// different FeatureSet.
func Init(fs cpuid.FeatureSet) {
	// Initialize all sizes.
	VirtualAddressBits = uintptr(fs.VirtualAddressBits())
	// TODO(gvisor.dev/issue/7349): introduce support for 5-level paging.
	// Four-level page tables allows to address up to 48-bit virtual
	// addresses.
	if VirtualAddressBits > 48 {
		VirtualAddressBits = 48
	}
	PhysicalAddressBits = uintptr(fs.PhysicalAddressBits())
	UserspaceSize = uintptr(1) << (VirtualAddressBits - 1)
	MaximumUserAddress = (UserspaceSize - 1) & ^uintptr(hostarch.PageSize-1)
	KernelStartAddress = ^uintptr(0) - (UserspaceSize - 1)

	// Initialize all functions.
	hasSMEP = fs.HasFeature(cpuid.X86FeatureSMEP)
	hasSMAP = fs.HasFeature(cpuid.X86FeatureSMAP)
	hasPCID = fs.HasFeature(cpuid.X86FeaturePCID)
	hasXSAVEOPT = fs.UseXsaveopt()
	hasXSAVE = fs.UseXsave()
	hasFSGSBASE = fs.HasFeature(cpuid.X86FeatureFSGSBase)
	validXCR0Mask = uintptr(fs.ValidXCR0Mask())
	if hasXSAVE {
		localXCR0 = xgetbv(0)
	}
}

func init() {
	// See Init, above.
	Init(cpuid.HostFeatureSet())
}
