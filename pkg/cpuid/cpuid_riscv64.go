// Copyright 2026 The gVisor Authors.
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

//go:build riscv64

package cpuid
import (
	"fmt"
	"io"
)

// FeatureSet for RISC-V contains CPU identification from /proc/cpuinfo.
//
// +stateify savable
type FeatureSet struct {
	hwCap     hwCap
	hartids   []uint64
	isa       string
	mmu       string
	mvendorid uint64
	marchid   uint64
	mimplid   uint64
}

// HasFeature returns true if the given feature is supported.
func (fs FeatureSet) HasFeature(f Feature) bool {
	return false
}

// ExtendedStateSize returns the number of bytes needed to save the "extended
// state" for this processor and the boundary it must be aligned to. Extended
// state includes floating point registers and other cpu state that's not
// associated with the normal task context.
func (fs FeatureSet) ExtendedStateSize() (size, align uint) {
	// RISC-V provides 32x64-bit floating point registers + fcsr.
	//
	// Ref arch/riscv/include/uapi/asm/ptrace.h
	// struct __riscv_d_ext_state {
	//        __u64 f[32];
	//        __u32 fcsr;
	// };
	return 264, 8
}

// WriteCPUInfoTo generates a section of one cpu in /proc/cpuinfo.
func (fs FeatureSet) WriteCPUInfoTo(cpu, numCPU uint, w io.Writer) {
	fmt.Fprintf(w, "processor\t: %d\n", cpu)
	if int(cpu) < len(fs.hartids) {
		fmt.Fprintf(w, "hart\t\t: %d\n", fs.hartids[cpu])
	}
	fmt.Fprintf(w, "isa\t\t: %s\n", fs.isa)
	fmt.Fprintf(w, "mmu\t\t: %s\n", fs.mmu)
	fmt.Fprintf(w, "\n")
}

// archFlagOrder is a no-op for riscv64.
func archFlagOrder(fn func(Feature)) {}

// archCheckHostCompatible is a noop on riscv64.
func (FeatureSet) archCheckHostCompatible(FeatureSet) error {
	return nil
}

// AllowedHWCap1 returns the HWCAP1 bits that the guest is allowed to depend
// on. RISC-V uses a single hwCap value.
func (fs FeatureSet) AllowedHWCap1() uint64 {
	return fs.hwCap.hwCap1
}

// AllowedHWCap2 returns the HWCAP2 bits. RISC-V does not use HWCAP2.
func (fs FeatureSet) AllowedHWCap2() uint64 {
	return fs.hwCap.hwCap2
}
