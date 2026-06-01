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

// Each Feature here corresponds 1:1 with one of the HWCAP_LOONGARCH_* bits
// above; HasFeature shifts (1 << Feature) and ANDs against fs.hwCap.hwCap1.
const (
	// LoongArch64FeatureCPUCFG indicates the CPUCFG instruction is available.
	LoongArch64FeatureCPUCFG Feature = iota

	// LoongArch64FeatureLAM indicates LoongArch AMO instructions are available.
	LoongArch64FeatureLAM

	// LoongArch64FeatureUAL indicates unaligned access is allowed.
	LoongArch64FeatureUAL

	// LoongArch64FeatureFPU indicates the basic floating-point unit is present.
	LoongArch64FeatureFPU

	// LoongArch64FeatureLSX indicates the 128-bit Loongson SIMD Extension is
	// available. gVisor on LoongArch64 does NOT save/restore LSX state across
	// context switches; this bit is kept here only for /proc/cpuinfo
	// reporting and is filtered out by allowedHWCap1 below.
	LoongArch64FeatureLSX

	// LoongArch64FeatureLASX indicates the 256-bit Loongson Advanced SIMD
	// Extension is available. Same caveat as LSX.
	LoongArch64FeatureLASX

	// LoongArch64FeatureCRC32 indicates hardware CRC32 instructions are
	// available.
	LoongArch64FeatureCRC32

	// LoongArch64FeatureCOMPLEX indicates complex-number FP instructions.
	LoongArch64FeatureCOMPLEX

	// LoongArch64FeatureCRYPTO indicates crypto instructions are available.
	LoongArch64FeatureCRYPTO
)


// allFeatures provides the reverse mapping from Feature to the
// /proc/cpuinfo flag plus a "supported" bit. The map ordering is
// irrelevant — archFlagOrder walks Feature values directly.
var allFeatures = map[Feature]allFeatureInfo{
	LoongArch64FeatureCPUCFG:  {"cpucfg", true},
	LoongArch64FeatureLAM:     {"lam", true},
	LoongArch64FeatureUAL:     {"ual", true},
	LoongArch64FeatureFPU:     {"fpu", true},
	LoongArch64FeatureLSX:     {"lsx", true},
	LoongArch64FeatureLASX:    {"lasx", true},
	LoongArch64FeatureCRC32:   {"crc32", true},
	LoongArch64FeatureCOMPLEX: {"complex", true},
	LoongArch64FeatureCRYPTO:  {"crypto", true},
}

// archFlagOrder iterates over Feature values in declaration order.
func archFlagOrder(fn func(Feature)) {
	for i := 0; i < len(allFeatures); i++ {
		fn(Feature(i))
	}
}
