// Copyright 2018 Google LLC
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

// +build i386 amd64

// Package cpuid provides basic functionality for creating and adjusting CPU
// feature sets.
//
// To use FeatureSets, one should start with an existing FeatureSet (either a
// known platform, or HostFeatureSet()) and then add, remove, and test for
// features as desired.
//
// For example: Test for hardware extended state saving, and if we don't have
// it, don't expose AVX, which cannot be saved with fxsave.
//
//   if !HostFeatureSet().HasFeature(X86FeatureXSAVE) {
//     exposedFeatures.Remove(X86FeatureAVX)
//   }
package cpuid

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/log"
)

// Feature is a unique identifier for a particular cpu feature. We just use an
// int as a feature number on x86. It corresponds to the bit position in the
// basic feature mask returned by a cpuid with eax=1.
type Feature int

// block is a collection of 32 Feature bits.
type block int

const blockSize = 32

// Feature bits are numbered according to "blocks". Each block is 32 bits, and
// feature bits from the same source (cpuid leaf/level) are in the same block.
func featureID(b block, bit int) Feature {
	return Feature(32*int(b) + bit)
}

// Block 0 constants are all of the "basic" feature bits returned by a cpuid in
// ecx with eax=1.
const (
	X86FeatureSSE3 Feature = iota
	X86FeaturePCLMULDQ
	X86FeatureDTES64
	X86FeatureMONITOR
	X86FeatureDSCPL
	X86FeatureVMX
	X86FeatureSMX
	X86FeatureEST
	X86FeatureTM2
	X86FeatureSSSE3 // Not a typo, "supplemental" SSE3.
	X86FeatureCNXTID
	X86FeatureSDBG
	X86FeatureFMA
	X86FeatureCX16
	X86FeatureXTPR
	X86FeaturePDCM
	_ // ecx bit 16 is reserved.
	X86FeaturePCID
	X86FeatureDCA
	X86FeatureSSE4_1
	X86FeatureSSE4_2
	X86FeatureX2APIC
	X86FeatureMOVBE
	X86FeaturePOPCNT
	X86FeatureTSCD
	X86FeatureAES
	X86FeatureXSAVE
	X86FeatureOSXSAVE
	X86FeatureAVX
	X86FeatureF16C
	X86FeatureRDRAND
	_ // ecx bit 31 is reserved.
)

// Block 1 constants are all of the "basic" feature bits returned by a cpuid in
// edx with eax=1.
const (
	X86FeatureFPU Feature = 32 + iota
	X86FeatureVME
	X86FeatureDE
	X86FeaturePSE
	X86FeatureTSC
	X86FeatureMSR
	X86FeaturePAE
	X86FeatureMCE
	X86FeatureCX8
	X86FeatureAPIC
	_ // edx bit 10 is reserved.
	X86FeatureSEP
	X86FeatureMTRR
	X86FeaturePGE
	X86FeatureMCA
	X86FeatureCMOV
	X86FeaturePAT
	X86FeaturePSE36
	X86FeaturePSN
	X86FeatureCLFSH
	_ // edx bit 20 is reserved.
	X86FeatureDS
	X86FeatureACPI
	X86FeatureMMX
	X86FeatureFXSR
	X86FeatureSSE
	X86FeatureSSE2
	X86FeatureSS
	X86FeatureHTT
	X86FeatureTM
	X86FeatureIA64
	X86FeaturePBE
)

// Block 2 bits are the "structured extended" features returned in ebx for
// eax=7, ecx=0.
const (
	X86FeatureFSGSBase Feature = 2*32 + iota
	X86FeatureTSC_ADJUST
	_ // ebx bit 2 is reserved.
	X86FeatureBMI1
	X86FeatureHLE
	X86FeatureAVX2
	X86FeatureFDP_EXCPTN_ONLY
	X86FeatureSMEP
	X86FeatureBMI2
	X86FeatureERMS
	X86FeatureINVPCID
	X86FeatureRTM
	X86FeatureCQM
	X86FeatureFPCSDS
	X86FeatureMPX
	X86FeatureRDT
	X86FeatureAVX512F
	X86FeatureAVX512DQ
	X86FeatureRDSEED
	X86FeatureADX
	X86FeatureSMAP
	X86FeatureAVX512IFMA
	X86FeaturePCOMMIT
	X86FeatureCLFLUSHOPT
	X86FeatureCLWB
	X86FeatureIPT // Intel processor trace.
	X86FeatureAVX512PF
	X86FeatureAVX512ER
	X86FeatureAVX512CD
	X86FeatureSHA
	X86FeatureAVX512BW
	X86FeatureAVX512VL
)

// Block 3 bits are the "extended" features returned in ecx for eax=7, ecx=0.
const (
	X86FeaturePREFETCHWT1 Feature = 3*32 + iota
	X86FeatureAVX512VBMI
	X86FeatureUMIP
	X86FeaturePKU
)

// Block 4 constants are for xsave capabilities in CPUID.(EAX=0DH,ECX=01H):EAX.
// The CPUID leaf is available only if 'X86FeatureXSAVE' is present.
const (
	X86FeatureXSAVEOPT Feature = 4*32 + iota
	X86FeatureXSAVEC
	X86FeatureXGETBV1
	X86FeatureXSAVES
	// EAX[31:4] are reserved.
)

// Block 5 constants are the extended feature bits in
// CPUID.(EAX=0x80000001):ECX. These are very sparse, and so the bit positions
// are assigned manually.
const (
	X86FeatureLAHF64    Feature = 5*32 + 0
	X86FeatureLZCNT     Feature = 5*32 + 5
	X86FeaturePREFETCHW Feature = 5*32 + 8
)

// Block 6 constants are the extended feature bits in
// CPUID.(EAX=0x80000001):EDX. These are very sparse, and so the bit positions
// are assigned manually.
const (
	X86FeatureSYSCALL Feature = 6*32 + 11
	X86FeatureNX      Feature = 6*32 + 20
	X86FeatureGBPAGES Feature = 6*32 + 26
	X86FeatureRDTSCP  Feature = 6*32 + 27
	X86FeatureLM      Feature = 6*32 + 29
	// These are not in the most recent intel manual. Not surprising... It
	// shouldn't matter but we should find where these bits come from and
	// support them. The linux strings are below for completeness.
	//X86FeatureMMXEXT
	//X86FeatureMP
	//X86FeatureFXSR_OPT
	//X86Feature3DNOWEXT
	//X86Feature3DNOW
	//X86FeatureMMXEXT:      "mmxext",
	//X86FeatureMP:          "mp",
	//X86FeatureFXSR_OPT:    "fxsr_opt",
	//X86Feature3DNOWEXT:    "3dnowext",
	//X86Feature3DNOW:       "3dnow",
)

// linuxBlockOrder defines the order in which linux organizes the feature
// blocks. Linux also tracks feature bits in 32-bit blocks, but in an order
// which doesn't match well here, so for the /proc/cpuinfo generation we simply
// re-map the blocks to Linux's ordering and then go through the bits in each
// block.
var linuxBlockOrder = []block{1, 6, 0, 5, 2, 4, 3}

// To make emulation of /proc/cpuinfo easy down the line, these names match the
// names of the basic features in Linux defined in
// arch/x86/kernel/cpu/capflags.c.
var x86FeatureStrings = map[Feature]string{
	// Block 0.
	X86FeatureSSE3:     "pni",
	X86FeaturePCLMULDQ: "pclmulqdq",
	X86FeatureDTES64:   "dtes64",
	X86FeatureMONITOR:  "monitor",
	X86FeatureDSCPL:    "ds_cpl",
	X86FeatureVMX:      "vmx",
	X86FeatureSMX:      "smx",
	X86FeatureEST:      "est",
	X86FeatureTM2:      "tm2",
	X86FeatureSSSE3:    "ssse3",
	X86FeatureCNXTID:   "cid",
	X86FeatureFMA:      "fma",
	X86FeatureCX16:     "cx16",
	X86FeatureXTPR:     "xtpr",
	X86FeaturePDCM:     "pdcm",
	X86FeaturePCID:     "pcid",
	X86FeatureDCA:      "dca",
	X86FeatureSSE4_1:   "sse4_1",
	X86FeatureSSE4_2:   "sse4_2",
	X86FeatureX2APIC:   "x2apic",
	X86FeatureMOVBE:    "movbe",
	X86FeaturePOPCNT:   "popcnt",
	X86FeatureTSCD:     "tsc_deadline_timer",
	X86FeatureAES:      "aes",
	X86FeatureXSAVE:    "xsave",
	X86FeatureAVX:      "avx",
	X86FeatureF16C:     "f16c",
	X86FeatureRDRAND:   "rdrand",

	// Block 1.
	X86FeatureFPU:   "fpu",
	X86FeatureVME:   "vme",
	X86FeatureDE:    "de",
	X86FeaturePSE:   "pse",
	X86FeatureTSC:   "tsc",
	X86FeatureMSR:   "msr",
	X86FeaturePAE:   "pae",
	X86FeatureMCE:   "mce",
	X86FeatureCX8:   "cx8",
	X86FeatureAPIC:  "apic",
	X86FeatureSEP:   "sep",
	X86FeatureMTRR:  "mtrr",
	X86FeaturePGE:   "pge",
	X86FeatureMCA:   "mca",
	X86FeatureCMOV:  "cmov",
	X86FeaturePAT:   "pat",
	X86FeaturePSE36: "pse36",
	X86FeaturePSN:   "pn",
	X86FeatureCLFSH: "clflush",
	X86FeatureDS:    "dts",
	X86FeatureACPI:  "acpi",
	X86FeatureMMX:   "mmx",
	X86FeatureFXSR:  "fxsr",
	X86FeatureSSE:   "sse",
	X86FeatureSSE2:  "sse2",
	X86FeatureSS:    "ss",
	X86FeatureHTT:   "ht",
	X86FeatureTM:    "tm",
	X86FeatureIA64:  "ia64",
	X86FeaturePBE:   "pbe",

	// Block 2.
	X86FeatureFSGSBase:   "fsgsbase",
	X86FeatureTSC_ADJUST: "tsc_adjust",
	X86FeatureBMI1:       "bmi1",
	X86FeatureHLE:        "hle",
	X86FeatureAVX2:       "avx2",
	X86FeatureSMEP:       "smep",
	X86FeatureBMI2:       "bmi2",
	X86FeatureERMS:       "erms",
	X86FeatureINVPCID:    "invpcid",
	X86FeatureRTM:        "rtm",
	X86FeatureCQM:        "cqm",
	X86FeatureMPX:        "mpx",
	X86FeatureRDT:        "rdt",
	X86FeatureAVX512F:    "avx512f",
	X86FeatureAVX512DQ:   "avx512dq",
	X86FeatureRDSEED:     "rdseed",
	X86FeatureADX:        "adx",
	X86FeatureSMAP:       "smap",
	X86FeatureCLWB:       "clwb",
	X86FeatureAVX512PF:   "avx512pf",
	X86FeatureAVX512ER:   "avx512er",
	X86FeatureAVX512CD:   "avx512cd",
	X86FeatureSHA:        "sha_ni",
	X86FeatureAVX512BW:   "avx512bw",
	X86FeatureAVX512VL:   "avx512vl",

	// Block 3.
	X86FeaturePREFETCHWT1: "prefetchwt1",
	X86FeatureAVX512VBMI:  "avx512vbmi",
	X86FeatureUMIP:        "umip",
	X86FeaturePKU:         "pku",

	// Block 4.
	X86FeatureXSAVEOPT: "xsaveopt",
	X86FeatureXSAVEC:   "xsavec",
	X86FeatureXGETBV1:  "xgetbv1",

	// Block 5.
	X86FeatureLAHF64:    "lahf_lm", // LAHF/SAHF in long mode
	X86FeatureLZCNT:     "abm",     // Advanced bit manipulation
	X86FeaturePREFETCHW: "3dnowprefetch",

	// Block 6.
	X86FeatureSYSCALL: "syscall",
	X86FeatureNX:      "nx",
	X86FeatureGBPAGES: "pdpe1gb",
	X86FeatureRDTSCP:  "rdtscp",
	X86FeatureLM:      "lm",
}

// These flags are parse only---they can be used for setting / unsetting the
// flags, but will not get printed out in /proc/cpuinfo.
var x86FeatureParseOnlyStrings = map[Feature]string{
	// Block 0.
	X86FeatureSDBG:    "sdbg",
	X86FeatureOSXSAVE: "osxsave",

	// Block 2.
	X86FeatureFDP_EXCPTN_ONLY: "fdp_excptn_only",
	X86FeatureFPCSDS:          "fpcsds",
	X86FeatureIPT:             "pt",
	X86FeatureCLFLUSHOPT:      "clfushopt",

	// Block 4.
	X86FeatureXSAVES: "xsaves",
}

// These are the default values of various FeatureSet fields.
const (
	defaultVendorID = "GenuineIntel"

	// These processor signature defaults are derived from the values
	// listed in Intel AN485 for i7/Xeon processors.
	defaultExtFamily  uint8 = 0
	defaultExtModel   uint8 = 1
	defaultType       uint8 = 0
	defaultFamily     uint8 = 0x06
	defaultModel      uint8 = 0x0a
	defaultSteppingID uint8 = 0
)

// Just a way to wrap cpuid function numbers.
type cpuidFunction uint32

// The constants below are the lower or "standard" cpuid functions. See Intel
// AN485 for detailed information about each one.
const (
	vendorID                 cpuidFunction = iota // Returns vendor ID and largest standard function.
	featureInfo                                   // Returns basic feature bits and processor signature.
	cacheDescriptors                              // Returns list of cache descriptors.
	serialNumber                                  // Returns processor serial number (obsolete on new hardware).
	deterministicCacheParams                      // Returns deterministic cache information. See AN485.
	monitorMwaitParams                            // Returns information about monitor/mwait instructions.
	powerParams                                   // Returns information about power management and thermal sensors.
	extendedFeatureInfo                           // Returns extended feature bits.
	_                                             // Function 8 is reserved.
	DCAParams                                     // Returns direct cache access information.
	pmcInfo                                       // Returns information about performance monitoring features.
	x2APICInfo                                    // Returns core/logical processor topology. See AN485 for details.
	_                                             // Function 0xc is reserved.
	xSaveInfo                                     // Returns information about extended state management.
)

// The "extended" functions start at 0x80000000. Intel AP-485 has information
// on these as well.
const (
	extendedFunctionInfo cpuidFunction = 0x80000000 + iota // Returns highest available extended function in eax.
	extendedFeatures                                       // Returns some extended feature bits in edx and ecx.
)

var cpuFreqMHz float64

// x86FeaturesFromString includes features from x86FeatureStrings and
// x86FeatureParseOnlyStrings.
var x86FeaturesFromString = make(map[string]Feature)

// FeatureFromString returns the Feature associated with the given feature
// string plus a bool to indicate if it could find the feature.
func FeatureFromString(s string) (Feature, bool) {
	f, b := x86FeaturesFromString[s]
	return f, b
}

// String implements fmt.Stringer.
func (f Feature) String() string {
	if s := f.flagString(false); s != "" {
		return s
	}
	return fmt.Sprintf("<cpuflag %d>", f)
}

func (f Feature) flagString(cpuinfoOnly bool) string {
	if s, ok := x86FeatureStrings[f]; ok {
		return s
	}
	if !cpuinfoOnly {
		return x86FeatureParseOnlyStrings[f]
	}
	return ""
}

// FeatureSet is a set of Features for a cpu.
//
// +stateify savable
type FeatureSet struct {
	// Set is the set of features that are enabled in this FeatureSet.
	Set map[Feature]bool

	// VendorID is the 12-char string returned in ebx:edx:ecx for eax=0.
	VendorID string

	// ExtendedFamily is part of the processor signature.
	ExtendedFamily uint8

	// ExtendedModel is part of the processor signature.
	ExtendedModel uint8

	// ProcessorType is part of the processor signature.
	ProcessorType uint8

	// Family is part of the processor signature.
	Family uint8

	// Model is part of the processor signature.
	Model uint8

	// SteppingID is part of the processor signature.
	SteppingID uint8
}

// FlagsString prints out supported CPU flags. If cpuinfoOnly is true, it is
// equivalent to the "flags" field in /proc/cpuinfo.
func (fs *FeatureSet) FlagsString(cpuinfoOnly bool) string {
	var s []string
	for _, b := range linuxBlockOrder {
		for i := 0; i < blockSize; i++ {
			if f := featureID(b, i); fs.Set[f] {
				if fstr := f.flagString(cpuinfoOnly); fstr != "" {
					s = append(s, fstr)
				}
			}
		}
	}
	return strings.Join(s, " ")
}

// CPUInfo is to generate a section of one cpu in /proc/cpuinfo. This is a
// minimal /proc/cpuinfo, it is missing some fields like "microcode" that are
// not always printed in Linux. The bogomips field is simply made up.
func (fs FeatureSet) CPUInfo(cpu uint) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "processor\t: %d\n", cpu)
	fmt.Fprintf(&b, "vendor_id\t: %s\n", fs.VendorID)
	fmt.Fprintf(&b, "cpu family\t: %d\n", ((fs.ExtendedFamily<<4)&0xff)|fs.Family)
	fmt.Fprintf(&b, "model\t\t: %d\n", ((fs.ExtendedModel<<4)&0xff)|fs.Model)
	fmt.Fprintf(&b, "model name\t: %s\n", "unknown") // Unknown for now.
	fmt.Fprintf(&b, "stepping\t: %s\n", "unknown")   // Unknown for now.
	fmt.Fprintf(&b, "cpu MHz\t\t: %.3f\n", cpuFreqMHz)
	fmt.Fprintln(&b, "fpu\t\t: yes")
	fmt.Fprintln(&b, "fpu_exception\t: yes")
	fmt.Fprintf(&b, "cpuid level\t: %d\n", uint32(xSaveInfo)) // Same as ax in vendorID.
	fmt.Fprintln(&b, "wp\t\t: yes")
	fmt.Fprintf(&b, "flags\t\t: %s\n", fs.FlagsString(true))
	fmt.Fprintf(&b, "bogomips\t: %.02f\n", cpuFreqMHz) // It's bogus anyway.
	fmt.Fprintf(&b, "clflush size\t: %d\n", 64)
	fmt.Fprintf(&b, "cache_alignment\t: %d\n", 64)
	fmt.Fprintf(&b, "address sizes\t: %d bits physical, %d bits virtual\n", 46, 48)
	fmt.Fprintln(&b, "power management:") // This is always here, but can be blank.
	fmt.Fprintln(&b, "")                  // The /proc/cpuinfo file ends with an extra newline.
	return b.String()
}

// Helper to convert 3 regs into 12-byte vendor ID.
func vendorIDFromRegs(bx, cx, dx uint32) string {
	bytes := make([]byte, 0, 12)
	for i := uint(0); i < 4; i++ {
		b := byte(bx >> (i * 8))
		bytes = append(bytes, b)
	}

	for i := uint(0); i < 4; i++ {
		b := byte(dx >> (i * 8))
		bytes = append(bytes, b)
	}

	for i := uint(0); i < 4; i++ {
		b := byte(cx >> (i * 8))
		bytes = append(bytes, b)
	}
	return string(bytes)
}

// ExtendedStateSize returns the number of bytes needed to save the "extended
// state" for this processor and the boundary it must be aligned to. Extended
// state includes floating point registers, and other cpu state that's not
// associated with the normal task context.
//
// Note: We can save some space here with an optimiazation where we use a
// smaller chunk of memory depending on features that are actually enabled.
// Currently we just use the largest possible size for simplicity (which is
// about 2.5K worst case, with avx512).
func (fs *FeatureSet) ExtendedStateSize() (size, align uint) {
	if fs.UseXsave() {
		// Leaf 0 of xsaveinfo function returns the size for currently
		// enabled xsave features in ebx, the maximum size if all valid
		// features are saved with xsave in ecx, and valid XCR0 bits in
		// edx:eax.
		_, _, maxSize, _ := HostID(uint32(xSaveInfo), 0)
		return uint(maxSize), 64
	}

	// If we don't support xsave, we fall back to fxsave, which requires
	// 512 bytes aligned to 16 bytes.
	return 512, 16
}

// ValidXCR0Mask returns the bits that may be set to 1 in control register
// XCR0.
func (fs *FeatureSet) ValidXCR0Mask() uint64 {
	if !fs.UseXsave() {
		return 0
	}
	eax, _, _, edx := HostID(uint32(xSaveInfo), 0)
	return uint64(edx)<<32 | uint64(eax)
}

// vendorIDRegs returns the 3 register values used to construct the 12-byte
// vendor ID string for eax=0.
func (fs *FeatureSet) vendorIDRegs() (bx, dx, cx uint32) {
	for i := uint(0); i < 4; i++ {
		bx |= uint32(fs.VendorID[i]) << (i * 8)
	}

	for i := uint(0); i < 4; i++ {
		dx |= uint32(fs.VendorID[i+4]) << (i * 8)
	}

	for i := uint(0); i < 4; i++ {
		cx |= uint32(fs.VendorID[i+8]) << (i * 8)
	}
	return
}

// signature returns the signature dword that's returned in eax when eax=1.
func (fs *FeatureSet) signature() uint32 {
	var s uint32
	s |= uint32(fs.SteppingID & 0xf)
	s |= uint32(fs.Model&0xf) << 4
	s |= uint32(fs.Family&0xf) << 8
	s |= uint32(fs.ProcessorType&0x3) << 12
	s |= uint32(fs.ExtendedModel&0xf) << 16
	s |= uint32(fs.ExtendedFamily&0xff) << 20
	return s
}

// Helper to deconstruct signature dword.
func signatureSplit(v uint32) (ef, em, pt, f, m, sid uint8) {
	sid = uint8(v & 0xf)
	m = uint8(v>>4) & 0xf
	f = uint8(v>>8) & 0xf
	pt = uint8(v>>12) & 0x3
	em = uint8(v>>16) & 0xf
	ef = uint8(v >> 20)
	return
}

// This factory function is only needed inside the package, package users
// should not be creating and using empty feature sets.
func newEmptyFeatureSet() *FeatureSet {
	return newFeatureSet(make(map[Feature]bool))
}

// newFeatureSet creates a new FeatureSet with sensible default values and the
// provided set of features.
func newFeatureSet(s map[Feature]bool) *FeatureSet {
	return &FeatureSet{
		Set:            s,
		VendorID:       defaultVendorID,
		ExtendedFamily: defaultExtFamily,
		ExtendedModel:  defaultExtModel,
		ProcessorType:  defaultType,
		Family:         defaultFamily,
		Model:          defaultModel,
		SteppingID:     defaultSteppingID,
	}
}

// Helper to convert blockwise feature bit masks into a set of features. Masks
// must be provided in order for each block, without skipping them. If a block
// does not matter for this feature set, 0 is specified.
func setFromBlockMasks(blocks ...uint32) map[Feature]bool {
	s := make(map[Feature]bool)
	for b, blockMask := range blocks {
		for i := 0; i < blockSize; i++ {
			if blockMask&1 != 0 {
				s[featureID(block(b), i)] = true
			}
			blockMask >>= 1
		}
	}
	return s
}

// blockMask returns the 32-bit mask associated with a block of features.
func (fs *FeatureSet) blockMask(b block) uint32 {
	var mask uint32
	for i := 0; i < blockSize; i++ {
		if fs.Set[featureID(b, i)] {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

// Remove removes a Feature from a FeatureSet. It ignores features
// that are not in the FeatureSet.
func (fs *FeatureSet) Remove(feature Feature) {
	delete(fs.Set, feature)
}

// Add adds a Feature to a FeatureSet. It ignores duplicate features.
func (fs *FeatureSet) Add(feature Feature) {
	fs.Set[feature] = true
}

// HasFeature tests whether or not a feature is in the given feature set.
func (fs *FeatureSet) HasFeature(feature Feature) bool {
	return fs.Set[feature]
}

// IsSubset returns true if the FeatureSet is a subset of the FeatureSet passed in.
// This is useful if you want to see if a FeatureSet is compatible with another
// FeatureSet, since you can only run with a given FeatureSet if it's a subset of
// the host's.
func (fs *FeatureSet) IsSubset(other *FeatureSet) bool {
	return fs.Subtract(other) == nil
}

// Subtract returns the features present in fs that are not present in other.
// If all features in fs are present in other, Subtract returns nil.
func (fs *FeatureSet) Subtract(other *FeatureSet) (diff map[Feature]bool) {
	for f := range fs.Set {
		if !other.Set[f] {
			if diff == nil {
				diff = make(map[Feature]bool)
			}
			diff[f] = true
		}
	}

	return
}

// TakeFeatureIntersection will set the features in `fs` to the intersection of
// the features in `fs` and `other` (effectively clearing any feature bits on
// `fs` that are not also set in `other`).
func (fs *FeatureSet) TakeFeatureIntersection(other *FeatureSet) {
	for f := range fs.Set {
		if !other.Set[f] {
			delete(fs.Set, f)
		}
	}
}

// EmulateID emulates a cpuid instruction based on the feature set.
func (fs *FeatureSet) EmulateID(origAx, origCx uint32) (ax, bx, cx, dx uint32) {
	switch cpuidFunction(origAx) {
	case vendorID:
		ax = uint32(xSaveInfo) // 0xd (xSaveInfo) is the highest function we support.
		bx, dx, cx = fs.vendorIDRegs()
	case featureInfo:
		// clflush line size (ebx bits[15:8]) hardcoded as 8. This
		// means cache lines of size 64 bytes.
		bx = 8 << 8
		cx = fs.blockMask(block(0))
		dx = fs.blockMask(block(1))
		ax = fs.signature()
	case xSaveInfo:
		if !fs.UseXsave() {
			return 0, 0, 0, 0
		}
		return HostID(uint32(xSaveInfo), origCx)
	case extendedFeatureInfo:
		if origCx != 0 {
			break // Only leaf 0 is supported.
		}
		bx = fs.blockMask(block(2))
		cx = fs.blockMask(block(3))
	case extendedFunctionInfo:
		// We only support showing the extended features.
		ax = uint32(extendedFeatures)
		cx = 0
	case extendedFeatures:
		cx = fs.blockMask(block(5))
		dx = fs.blockMask(block(6))
	}

	return
}

// UseXsave returns the choice of fp state saving instruction.
func (fs *FeatureSet) UseXsave() bool {
	return fs.HasFeature(X86FeatureXSAVE) && fs.HasFeature(X86FeatureOSXSAVE)
}

// UseXsaveopt returns true if 'fs' supports the "xsaveopt" instruction.
func (fs *FeatureSet) UseXsaveopt() bool {
	return fs.UseXsave() && fs.HasFeature(X86FeatureXSAVEOPT)
}

// HostID executes a native CPUID instruction.
func HostID(axArg, cxArg uint32) (ax, bx, cx, dx uint32)

// HostFeatureSet uses cpuid to get host values and construct a feature set
// that matches that of the host machine. Note that there are several places
// where there appear to be some unnecessary assignments between register names
// (ax, bx, cx, or dx) and featureBlockN variables. This is to explicitly show
// where the different feature blocks come from, to make the code easier to
// inspect and read.
func HostFeatureSet() *FeatureSet {
	// eax=0 gets max supported feature and vendor ID.
	_, bx, cx, dx := HostID(0, 0)
	vendorID := vendorIDFromRegs(bx, cx, dx)

	// eax=1 gets basic features in ecx:edx.
	ax, _, cx, dx := HostID(1, 0)
	featureBlock0 := cx
	featureBlock1 := dx
	ef, em, pt, f, m, sid := signatureSplit(ax)

	// eax=7, ecx=0 gets extended features in ecx:ebx.
	_, bx, cx, _ = HostID(7, 0)
	featureBlock2 := bx
	featureBlock3 := cx

	// Leaf 0xd is supported only if CPUID.1:ECX.XSAVE[bit 26] is set.
	var featureBlock4 uint32
	if (featureBlock0 & (1 << 26)) != 0 {
		featureBlock4, _, _, _ = HostID(uint32(xSaveInfo), 1)
	}

	// eax=0x80000000 gets supported extended levels. We use this to
	// determine if there are any non-zero block 4 or block 6 bits to find.
	var featureBlock5, featureBlock6 uint32
	if ax, _, _, _ := HostID(uint32(extendedFunctionInfo), 0); ax >= uint32(extendedFeatures) {
		// eax=0x80000001 gets AMD added feature bits.
		_, _, cx, dx = HostID(uint32(extendedFeatures), 0)
		featureBlock5 = cx
		featureBlock6 = dx
	}

	set := setFromBlockMasks(featureBlock0, featureBlock1, featureBlock2, featureBlock3, featureBlock4, featureBlock5, featureBlock6)
	return &FeatureSet{
		Set:            set,
		VendorID:       vendorID,
		ExtendedFamily: ef,
		ExtendedModel:  em,
		ProcessorType:  pt,
		Family:         f,
		Model:          m,
		SteppingID:     sid,
	}
}

// Reads max cpu frequency from host /proc/cpuinfo. Must run before
// whitelisting. This value is used to create the fake /proc/cpuinfo from a
// FeatureSet.
func initCPUFreq() {
	cpuinfob, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		// Leave it as 0... The standalone VDSO bails out in the same
		// way.
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	cpuinfo := string(cpuinfob)

	// We get the value straight from host /proc/cpuinfo. On machines with
	// frequency scaling enabled, this will only get the current value
	// which will likely be innacurate. This is fine on machines with
	// frequency scaling disabled.
	for _, line := range strings.Split(cpuinfo, "\n") {
		if strings.Contains(line, "cpu MHz") {
			splitMHz := strings.Split(line, ":")
			if len(splitMHz) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed cpu MHz line")
				return
			}

			// If there was a problem, leave cpuFreqMHz as 0.
			var err error
			cpuFreqMHz, err = strconv.ParseFloat(strings.TrimSpace(splitMHz[1]), 64)
			if err != nil {
				log.Warningf("Could not parse cpu MHz value %v: %v", splitMHz[1], err)
				cpuFreqMHz = 0
				return
			}
			return
		}
	}
	log.Warningf("Could not parse /proc/cpuinfo, it is empty or does not contain cpu MHz")
}

func initFeaturesFromString() {
	for f, s := range x86FeatureStrings {
		x86FeaturesFromString[s] = f
	}
	for f, s := range x86FeatureParseOnlyStrings {
		x86FeaturesFromString[s] = f
	}
}

func init() {
	// initCpuFreq must be run before whitelists are enabled.
	initCPUFreq()
	initFeaturesFromString()
}
