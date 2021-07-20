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

// writeFS sets the FS base address (selects one of wrfsbase or wrfsmsr).
func writeFS(addr uintptr)

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
		WriteGS = wrgsbase
	} else {
		WriteGS = wrgsmsr
	}
}
