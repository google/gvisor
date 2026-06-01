// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

package cpuid

import (
	"fmt"
	"io"
)

// FeatureSet for LoongArch64. Like arm64, there's no in-CPU CPUID-equivalent
// discoverable from userspace; the kernel exposes capabilities via HWCAP bits
// in the auxiliary vector (see arch/loongarch/include/uapi/asm/hwcap.h).
//
// +stateify savable
type FeatureSet struct {
	hwCap      hwCap
	cpuFreqMHz float64
	cpuModel   string
}

// CPUModel returns the model name from /proc/cpuinfo, e.g. "Loongson-3A5000".
func (fs FeatureSet) CPUModel() string {
	return fs.cpuModel
}

// ExtendedStateSize returns the size and alignment of the extended FPU state
// area. gVisor on LoongArch64 saves only the base 32x64-bit FP registers plus
// FCC / FCSR; LSX (128b) and LASX (256b) state is not saved.
//
// Layout matches the kernel's struct user_fp_state:
//
//	struct user_fp_state {
//	    __u64 fpr[32];          // 32 * 8 = 256 bytes
//	    __u64 fcc;              // 8 bytes
//	    __u32 fcsr;             // 4 bytes
//	};
//
// Rounded up to 8-byte alignment.
func (fs FeatureSet) ExtendedStateSize() (size, align uint) {
	return 272, 8
}

// HasFeature checks for the presence of a feature.
func (fs FeatureSet) HasFeature(feature Feature) bool {
	return fs.hwCap.hwCap1&(1<<feature) != 0
}

// WriteCPUInfoTo generates a single CPU entry for /proc/cpuinfo. This is a
// minimal version; BogoMIPS is bogus by design.
func (fs FeatureSet) WriteCPUInfoTo(cpu, numCPU uint, w io.Writer) {
	fmt.Fprintf(w, "processor\t\t: %d\n", cpu)
	fmt.Fprintf(w, "package\t\t\t: 0\n")
	fmt.Fprintf(w, "core\t\t\t: %d\n", cpu)
	if fs.cpuModel != "" {
		fmt.Fprintf(w, "CPU Family\t\t: Loongson-64bit\n")
		fmt.Fprintf(w, "Model Name\t\t: %s\n", fs.cpuModel)
	}
	fmt.Fprintf(w, "CPU Revision\t\t: 0x00\n")
	fmt.Fprintf(w, "FPU Revision\t\t: 0x00\n")
	fmt.Fprintf(w, "CPU MHz\t\t\t: %.02f\n", fs.cpuFreqMHz)
	fmt.Fprintf(w, "BogoMIPS\t\t: %.02f\n", fs.cpuFreqMHz*2)
	fmt.Fprintf(w, "TLB Entries\t\t: 2112\n")
	fmt.Fprintf(w, "Address Sizes\t\t: 48 bits physical, 48 bits virtual\n")
	fmt.Fprintf(w, "ISA\t\t\t: loongarch32 loongarch64\n")
	fmt.Fprintf(w, "Features\t\t: %s\n", fs.FlagString())
	fmt.Fprintf(w, "Hardware Watchpoints\t: iwatch count: 0, dwatch count: 0\n")
	fmt.Fprintf(w, "\n")
}

// Fixed returns the same feature set.
func (fs FeatureSet) Fixed() FeatureSet {
	return fs
}

// Intersect is not supported on LoongArch64.
func (fs FeatureSet) Intersect(allowedFeatures map[Feature]struct{}) (FeatureSet, error) {
	return FeatureSet{}, fmt.Errorf("FeatureSet intersection is not supported on LoongArch64")
}

// archCheckHostCompatible is a noop on LoongArch64.
func (FeatureSet) archCheckHostCompatible(FeatureSet) error {
	return nil
}

// AllowedHWCap1 returns the HWCAP1 bits the guest may rely on. LSX and LASX
// are intentionally filtered out because the gVisor LoongArch port does not
// save/restore vector state across context switches.
func (fs FeatureSet) AllowedHWCap1() uint64 {
	const allowed = HWCAP_LOONGARCH_CPUCFG |
		HWCAP_LOONGARCH_LAM |
		HWCAP_LOONGARCH_UAL |
		HWCAP_LOONGARCH_FPU |
		HWCAP_LOONGARCH_CRC32
	return fs.hwCap.hwCap1 & uint64(allowed)
}

// AllowedHWCap2 returns the HWCAP2 bits the guest may rely on. LoongArch
// currently does not define HWCAP2 in mainline Linux.
func (fs FeatureSet) AllowedHWCap2() uint64 {
	return 0
}
