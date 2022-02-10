// Copyright 2020 The gVisor Authors.
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

package cpuid

import (
	"fmt"
	"io"
)

// FeatureSet for ARM64 is defined as a static set of bits.
//
// ARM64 doesn't have a CPUID equivalent, which means it has no architected
// discovery mechanism for hardware features available to userspace code at
// EL0. The kernel exposes the presence of these features to userspace through
// a set of flags(HWCAP/HWCAP2) bits, exposed in the auxiliary vector. See
// Documentation/arm64/elf_hwcaps.rst for more info.
//
// Currently, only the HWCAP bits are supported.
//
// +stateify savable
type FeatureSet struct {
	hwCap      uint
	cpuFreqMHz float64
	cpuImplHex uint64
	cpuArchDec uint64
	cpuVarHex  uint64
	cpuPartHex uint64
	cpuRevDec  uint64
}

// CPUImplementer is part of the processor signature.
func (fs FeatureSet) CPUImplementer() uint8 {
	return uint8(fs.cpuImplHex)
}

// CPUArchitecture is part of the processor signature.
func (fs FeatureSet) CPUArchitecture() uint8 {
	return uint8(fs.cpuArchDec)
}

// CPUVariant is part of the processor signature.
func (fs FeatureSet) CPUVariant() uint8 {
	return uint8(fs.cpuVarHex)
}

// CPUPartnum is part of the processor signature.
func (fs FeatureSet) CPUPartnum() uint16 {
	return uint16(fs.cpuPartHex)
}

// CPURevision is part of the processor signature.
func (fs FeatureSet) CPURevision() uint8 {
	return uint8(fs.cpuRevDec)
}

// ExtendedStateSize returns the number of bytes needed to save the "extended
// state" for this processor and the boundary it must be aligned to. Extended
// state includes floating point(NEON) registers, and other cpu state that's not
// associated with the normal task context.
func (fs FeatureSet) ExtendedStateSize() (size, align uint) {
	// ARMv8 provide 32x128bits NEON registers.
	//
	// Ref arch/arm64/include/uapi/asm/ptrace.h
	// struct user_fpsimd_state {
	//        __uint128_t     vregs[32];
	//        __u32           fpsr;
	//	  __u32           fpcr;
	//	  __u32           __reserved[2];
	// };
	return 528, 16
}

// HasFeature checks for the presence of a feature.
func (fs FeatureSet) HasFeature(feature Feature) bool {
	return fs.hwCap&(1<<feature) != 0
}

// WriteCPUInfoTo is to generate a section of one cpu in /proc/cpuinfo. This is
// a minimal /proc/cpuinfo, and the bogomips field is simply made up.
func (fs FeatureSet) WriteCPUInfoTo(cpu uint, w io.Writer) {
	fmt.Fprintf(w, "processor\t: %d\n", cpu)
	fmt.Fprintf(w, "BogoMIPS\t: %.02f\n", fs.cpuFreqMHz) // It's bogus anyway.
	fmt.Fprintf(w, "Features\t\t: %s\n", fs.FlagString())
	fmt.Fprintf(w, "CPU implementer\t: 0x%x\n", fs.cpuImplHex)
	fmt.Fprintf(w, "CPU architecture\t: %d\n", fs.cpuArchDec)
	fmt.Fprintf(w, "CPU variant\t: 0x%x\n", fs.cpuVarHex)
	fmt.Fprintf(w, "CPU part\t: 0x%x\n", fs.cpuPartHex)
	fmt.Fprintf(w, "CPU revision\t: %d\n", fs.cpuRevDec)
	fmt.Fprintf(w, "\n") // The /proc/cpuinfo file ends with an extra newline.
}

// archCheckHostCompatible is a noop on arm64.
func (FeatureSet) archCheckHostCompatible(FeatureSet) error {
	return nil
}
