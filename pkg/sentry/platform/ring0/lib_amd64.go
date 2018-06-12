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

// +build amd64

package ring0

import (
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
)

// LoadFloatingPoint loads floating point state by the most efficient mechanism
// available (set by Init).
var LoadFloatingPoint func(*byte)

// SaveFloatingPoint saves floating point state by the most efficient mechanism
// available (set by Init).
var SaveFloatingPoint func(*byte)

// fxrstor uses fxrstor64 to load floating point state.
func fxrstor(*byte)

// xrstor uses xrstor to load floating point state.
func xrstor(*byte)

// fxsave uses fxsave64 to save floating point state.
func fxsave(*byte)

// xsave uses xsave to save floating point state.
func xsave(*byte)

// xsaveopt uses xsaveopt to save floating point state.
func xsaveopt(*byte)

// WriteFS sets the GS address (set by init).
var WriteFS func(addr uintptr)

// wrfsbase writes to the GS base address.
func wrfsbase(addr uintptr)

// wrfsmsr writes to the GS_BASE MSR.
func wrfsmsr(addr uintptr)

// WriteGS sets the GS address (set by init).
var WriteGS func(addr uintptr)

// wrgsbase writes to the GS base address.
func wrgsbase(addr uintptr)

// wrgsmsr writes to the GS_BASE MSR.
func wrgsmsr(addr uintptr)

// writeCR3 writes the CR3 value.
func writeCR3(phys uintptr)

// readCR3 reads the current CR3 value.
func readCR3() uintptr

// readCR2 reads the current CR2 value.
func readCR2() uintptr

// jumpToKernel jumps to the kernel version of the current RIP.
func jumpToKernel()

// jumpToUser jumps to the user version of the current RIP.
func jumpToUser()

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
	hasPCID       bool
	hasXSAVEOPT   bool
	hasXSAVE      bool
	hasFSGSBASE   bool
	validXCR0Mask uintptr
)

// Init sets function pointers based on architectural features.
//
// This must be called prior to using ring0.
func Init(featureSet *cpuid.FeatureSet) {
	hasSMEP = featureSet.HasFeature(cpuid.X86FeatureSMEP)
	hasPCID = featureSet.HasFeature(cpuid.X86FeaturePCID)
	hasXSAVEOPT = featureSet.UseXsaveopt()
	hasXSAVE = featureSet.UseXsave()
	hasFSGSBASE = featureSet.HasFeature(cpuid.X86FeatureFSGSBase)
	validXCR0Mask = uintptr(featureSet.ValidXCR0Mask())
	if hasXSAVEOPT {
		SaveFloatingPoint = xsaveopt
		LoadFloatingPoint = xrstor
	} else if hasXSAVE {
		SaveFloatingPoint = xsave
		LoadFloatingPoint = xrstor
	} else {
		SaveFloatingPoint = fxsave
		LoadFloatingPoint = fxrstor
	}
	if hasFSGSBASE {
		WriteFS = wrfsbase
		WriteGS = wrgsbase
	} else {
		WriteFS = wrfsmsr
		WriteGS = wrgsmsr
	}
}
