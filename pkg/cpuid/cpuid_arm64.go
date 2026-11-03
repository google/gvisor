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
	hwCap      hwCap
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
	//        __u32           fpcr;
	//        __u32           __reserved[2];
	// };
	return 528, 16
}

// HasFeature checks for the presence of a feature.
func (fs FeatureSet) HasFeature(feature Feature) bool {
	return fs.hwCap.hwCap1&(1<<feature) != 0
}

// HasPointerAuth returns true if address pointer authentication is supported
// (HWCAP_PACA).
func (fs FeatureSet) HasPointerAuth() bool {
	return fs.hwCap.hwCap1&HWCAP_PACA != 0
}

// CPUFreqMHz returns the CPU frequency to report in /proc/cpuinfo.
func (fs FeatureSet) CPUFreqMHz() float64 {
	return fs.cpuFreqMHz
}

// WriteCPUInfoTo is to generate a section of one cpu in /proc/cpuinfo. This is
// a minimal /proc/cpuinfo, and the bogomips field is simply made up. freqMHz
// is reported as the CPU frequency; see CPUFreqMHz.
func (fs FeatureSet) WriteCPUInfoTo(cpu, numCPU uint, freqMHz float64, w io.Writer) {
	fmt.Fprintf(w, "processor\t: %d\n", cpu)
	fmt.Fprintf(w, "BogoMIPS\t: %.02f\n", freqMHz) // It's bogus anyway.
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

// AllowedHWCap1 returns the HWCAP1 bits that the guest is allowed to depend
// on.
func (fs FeatureSet) AllowedHWCap1() uint64 {
	// Pick a set of safe HWCAPS to expose. These do not rely on cpu state
	// that gvisor does not restore after a context switch.
	allowed := HWCAP_AES |
		HWCAP_ASIMD |
		HWCAP_ASIMDDP |
		HWCAP_ASIMDFHM |
		HWCAP_ASIMDHP |
		HWCAP_ASIMDRDM |
		HWCAP_ATOMICS |
		HWCAP_CRC32 |
		HWCAP_DCPOP |
		HWCAP_DIT |
		HWCAP_EVTSTRM |
		HWCAP_FCMA |
		HWCAP_FLAGM |
		HWCAP_FP |
		HWCAP_FPHP |
		HWCAP_ILRCPC |
		HWCAP_JSCVT |
		HWCAP_LRCPC |
		HWCAP_PMULL |
		HWCAP_SHA1 |
		HWCAP_SHA2 |
		HWCAP_SHA3 |
		HWCAP_SHA512 |
		HWCAP_SM3 |
		HWCAP_SM4 |
		HWCAP_USCAT
	return fs.hwCap.hwCap1 & uint64(allowed)
}

// AllowedHWCap2 returns the HWCAP2 bits that the guest is allowed to depend
// on.
func (fs FeatureSet) AllowedHWCap2() uint64 {
	// We don't expose anything here yet, but this could be expanded to
	// include features do not rely on cpu state that is not restored after
	// a context switch.
	allowed := 0
	return fs.hwCap.hwCap2 & uint64(allowed)
}

// UnsetFSGSBASE unsets features that should not be exposed to the guest workload.
func (fs FeatureSet) UnsetFSGSBASE() FeatureSet {
	return fs
}

// IDRegister returns what an application reads from the ID register
// S3_0_C0_C<crm>_<op2> (MIDR_EL1, MPIDR_EL1, REVIDR_EL1 and the
// ID_AA64*_EL1 registers) with MRS, or false if Linux makes the read an
// undefined instruction.
//
// Linux emulates these reads for applications (see
// Documentation/arch/arm64/cpu-feature-registers.rst): MIDR_EL1 reads as is,
// MPIDR_EL1 as only its RES1 bit, and REVIDR_EL1 as 0. The ID_AA64*_EL1
// registers show only the user-visible fields of the features Linux exposes,
// and the rest of the space reads as 0. Here the ID_AA64*_EL1 fields are
// those of the features in AllowedHWCap1, so they agree with AT_HWCAP.
func (fs FeatureSet) IDRegister(crm, op2 uint8) (uint64, bool) {
	switch {
	case crm == 0:
		switch op2 {
		case 0: // MIDR_EL1. The architecture field reads 0xf on AArch64.
			return (fs.cpuImplHex&0xff)<<24 | (fs.cpuVarHex&0xf)<<20 | 0xf<<16 |
				(fs.cpuPartHex&0xfff)<<4 | fs.cpuRevDec&0xf, true
		case 5: // MPIDR_EL1.
			return 1 << 31, true
		case 6: // REVIDR_EL1.
			return 0, true
		}
		return 0, false
	case crm == 1 || crm > 7:
		// The AArch32 registers at CRm 1, and anything outside the ID
		// space.
		return 0, false
	}
	hwCap := fs.AllowedHWCap1()
	field := func(feature uint64, shift uint, value uint64) uint64 {
		if hwCap&feature == 0 {
			return 0
		}
		return value << shift
	}
	// Where two features share a field, the larger value includes the
	// smaller: AES 2 is AES with PMULL, for example.
	switch [2]uint8{crm, op2} {
	case [2]uint8{4, 0}: // ID_AA64PFR0_EL1.
		v := uint64(1) | 1<<4 // EL0 and EL1: AArch64 only.
		// FP and AdvSIMD: 0 is implemented, 1 is implemented with half
		// precision, and 0xf is not implemented.
		switch {
		case hwCap&HWCAP_FPHP != 0:
			v |= 1 << 16
		case hwCap&HWCAP_FP == 0:
			v |= 0xf << 16
		}
		switch {
		case hwCap&HWCAP_ASIMDHP != 0:
			v |= 1 << 20
		case hwCap&HWCAP_ASIMD == 0:
			v |= 0xf << 20
		}
		return v | field(HWCAP_DIT, 48, 1), true
	case [2]uint8{6, 0}: // ID_AA64ISAR0_EL1.
		return max(field(HWCAP_AES, 4, 1), field(HWCAP_PMULL, 4, 2)) |
			field(HWCAP_SHA1, 8, 1) |
			max(field(HWCAP_SHA2, 12, 1), field(HWCAP_SHA512, 12, 2)) |
			field(HWCAP_CRC32, 16, 1) |
			field(HWCAP_ATOMICS, 20, 2) |
			field(HWCAP_ASIMDRDM, 28, 1) |
			field(HWCAP_SHA3, 32, 1) |
			field(HWCAP_SM3, 36, 1) |
			field(HWCAP_SM4, 40, 1) |
			field(HWCAP_ASIMDDP, 44, 1) |
			field(HWCAP_ASIMDFHM, 48, 1) |
			field(HWCAP_FLAGM, 52, 1), true
	case [2]uint8{6, 1}: // ID_AA64ISAR1_EL1.
		return field(HWCAP_DCPOP, 0, 1) |
			field(HWCAP_JSCVT, 12, 1) |
			field(HWCAP_FCMA, 16, 1) |
			max(field(HWCAP_LRCPC, 20, 1), field(HWCAP_ILRCPC, 20, 2)), true
	case [2]uint8{7, 2}: // ID_AA64MMFR2_EL1.
		return field(HWCAP_USCAT, 32, 1), true
	}
	// The other registers, the SVE ones among them, describe no
	// feature in AllowedHWCap1.
	return 0, true
}

// EmulateIDRegisterRead returns the destination register of inst and the
// value it reads, if inst is "MRS <Xt>, S3_0_C0_C<CRm>_<op2>", a read of an ID
// register that IDRegister emulates. Register 31 is XZR here.
func (fs FeatureSet) EmulateIDRegisterRead(inst uint32) (rt uint32, value uint64, ok bool) {
	// MRS is 1101010100 1 op0[1:0] op1[2:0] CRn[3:0] CRm[3:0] op2[2:0]
	// Rt[4:0], and the ID registers have op0 3, op1 0 and CRn 0.
	if inst&0xfffff000 != 0xd5380000 {
		return 0, 0, false
	}
	value, ok = fs.IDRegister(uint8(inst>>8&0xf), uint8(inst>>5&0x7))
	return inst & 0x1f, value, ok
}
