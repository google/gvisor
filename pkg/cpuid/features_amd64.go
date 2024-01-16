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

//go:build amd64
// +build amd64

package cpuid

// block is a collection of 32 Feature bits.
type block int

// blockSize is the number of bits in a single block.
const blockSize = 32

// featureID returns the feature identified by the given block and bit.
//
// Feature bits are numbered according to "blocks". Each block is 32 bits, and
// feature bits from the same source (cpuid leaf/level) are in the same block.
func featureID(b block, bit int) Feature {
	return Feature(blockSize*int(b) + bit)
}

// block returns the block associated with the feature.
func (f Feature) block() block {
	return block(f / blockSize)
}

// Bit returns the bit associated with the feature.
func (f Feature) bit() uint32 {
	return uint32(1 << (f % blockSize))
}

// ChangeableSet is a feature set that can allows changes.
type ChangeableSet interface {
	Query(in In) Out
	Set(in In, out Out)
}

// Set sets the given feature.
func (f Feature) Set(s ChangeableSet) {
	f.set(s, true)
}

// Unset unsets the given feature.
func (f Feature) Unset(s ChangeableSet) {
	f.set(s, false)
}

// set sets the given feature.
func (f Feature) set(s ChangeableSet, on bool) {
	switch f.block() {
	case 0:
		out := s.Query(In{Eax: uint32(featureInfo)})
		if on {
			out.Ecx |= f.bit()
		} else {
			out.Ecx &^= f.bit()
		}
		s.Set(In{Eax: uint32(featureInfo)}, out)
	case 1:
		out := s.Query(In{Eax: uint32(featureInfo)})
		if on {
			out.Edx |= f.bit()
		} else {
			out.Edx &^= f.bit()
		}
		s.Set(In{Eax: uint32(featureInfo)}, out)
	case 2:
		out := s.Query(In{Eax: uint32(extendedFeatureInfo)})
		if on {
			out.Ebx |= f.bit()
		} else {
			out.Ebx &^= f.bit()
		}
		s.Set(In{Eax: uint32(extendedFeatureInfo)}, out)
	case 3:
		out := s.Query(In{Eax: uint32(extendedFeatureInfo)})
		if on {
			out.Ecx |= f.bit()
		} else {
			out.Ecx &^= f.bit()
		}
		s.Set(In{Eax: uint32(extendedFeatureInfo)}, out)
	case 4:
		// Need to turn on the bit in block 0.
		out := s.Query(In{Eax: uint32(featureInfo)})
		out.Ecx |= (1 << 26)
		s.Set(In{Eax: uint32(featureInfo)}, out)

		out = s.Query(In{Eax: xSaveInfoSub.eax(), Ecx: xSaveInfoSub.ecx()})
		if on {
			out.Eax |= f.bit()
		} else {
			out.Eax &^= f.bit()
		}
		s.Set(In{Eax: xSaveInfoSub.eax(), Ecx: xSaveInfoSub.ecx()}, out)
	case 5, 6:
		// Need to enable extended features.
		out := s.Query(In{Eax: uint32(extendedFunctionInfo)})
		if out.Eax < uint32(extendedFeatures) {
			out.Eax = uint32(extendedFeatures)
		}
		s.Set(In{Eax: uint32(extendedFunctionInfo)}, out)
		out = s.Query(In{Eax: uint32(extendedFeatures)})
		if f.block() == 5 {
			if on {
				out.Ecx |= f.bit()
			} else {
				out.Ecx &^= f.bit()
			}
		} else {
			if on {
				out.Edx |= f.bit()
			} else {
				out.Edx &^= f.bit()
			}
		}
		s.Set(In{Eax: uint32(extendedFeatures)}, out)
	case 7:
		out := s.Query(In{Eax: uint32(extendedFeatureInfo)})
		if on {
			out.Edx |= f.bit()
		} else {
			out.Edx &^= f.bit()
		}
		s.Set(In{Eax: uint32(extendedFeatureInfo)}, out)
	}
}

// check checks for the given feature.
//
//go:nosplit
func (f Feature) check(fs FeatureSet) bool {
	switch f.block() {
	case 0:
		_, _, cx, _ := fs.query(featureInfo)
		return (cx & f.bit()) != 0
	case 1:
		_, _, _, dx := fs.query(featureInfo)
		return (dx & f.bit()) != 0
	case 2:
		_, bx, _, _ := fs.query(extendedFeatureInfo)
		return (bx & f.bit()) != 0
	case 3:
		_, _, cx, _ := fs.query(extendedFeatureInfo)
		return (cx & f.bit()) != 0
	case 4:
		// Need to check appropriate bit in block 0.
		_, _, cx, _ := fs.query(featureInfo)
		if (cx & (1 << 26)) == 0 {
			return false
		}
		ax, _, _, _ := fs.query(xSaveInfoSub)
		return (ax & f.bit()) != 0
	case 5, 6:
		// eax=0x80000000 gets supported extended levels. We use this
		// to determine if there are any non-zero block 4 or block 6
		// bits to find.
		ax, _, _, _ := fs.query(extendedFunctionInfo)
		if ax >= uint32(extendedFeatures) {
			_, _, cx, dx := fs.query(extendedFeatures)
			if f.block() == 5 {
				return (cx & f.bit()) != 0
			}
			// Ignore features duplicated from block 1 on AMD.
			// These bits are reserved on Intel.
			return ((dx &^ block6DuplicateMask) & f.bit()) != 0
		}
		return false
	case 7:
		_, _, _, dx := fs.query(extendedFeatureInfo)
		return (dx & f.bit()) != 0
	default:
		return false
	}
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
	X86FeatureHypervisor
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
	X86FeatureOSPKE
	X86FeatureWAITPKG
	X86FeatureAVX512_VBMI2
	X86FeatureCET_SS
	X86FeatureGFNI
	X86FeatureVAES
	X86FeatureVPCLMULQDQ
	X86FeatureAVX512_VNNI
	X86FeatureAVX512_BITALG
	X86FeatureTME
	X86FeatureAVX512_VPOPCNTDQ
	_ // ecx bit 15 is reserved
	X86FeatureLA57
	// ecx bits 17-21 are reserved
	_
	_
	_
	_
	_
	X86FeatureRDPID
	// ecx bits 23-24 are reserved
	_
	_
	X86FeatureCLDEMOTE
	_ // ecx bit 26 is reserved
	X86FeatureMOVDIRI
	X86FeatureMOVDIR64B
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
// CPUID.(EAX=0x80000001):ECX.
const (
	X86FeatureLAHF64 Feature = 5*32 + iota
	X86FeatureCMP_LEGACY
	X86FeatureSVM
	X86FeatureEXTAPIC
	X86FeatureCR8_LEGACY
	X86FeatureLZCNT
	X86FeatureSSE4A
	X86FeatureMISALIGNSSE
	X86FeaturePREFETCHW
	X86FeatureOSVW
	X86FeatureIBS
	X86FeatureXOP
	X86FeatureSKINIT
	X86FeatureWDT
	_ // ecx bit 14 is reserved.
	X86FeatureLWP
	X86FeatureFMA4
	X86FeatureTCE
	_ // ecx bit 18 is reserved.
	_ // ecx bit 19 is reserved.
	_ // ecx bit 20 is reserved.
	X86FeatureTBM
	X86FeatureTOPOLOGY
	X86FeaturePERFCTR_CORE
	X86FeaturePERFCTR_NB
	_ // ecx bit 25 is reserved.
	X86FeatureBPEXT
	X86FeaturePERFCTR_TSC
	X86FeaturePERFCTR_LLC
	X86FeatureMWAITX
	X86FeatureADMSKEXTN
	_ // ecx bit 31 is reserved.
)

// Block 6 constants are the extended feature bits in
// CPUID.(EAX=0x80000001):EDX.
//
// These are sparse, and so the bit positions are assigned manually.
const (
	// On AMD, EDX[24:23] | EDX[17:12] | EDX[9:0] are duplicate features
	// also defined in block 1 (in identical bit positions). Those features
	// are not listed here.
	block6DuplicateMask = 0x183f3ff

	X86FeatureSYSCALL  Feature = 6*32 + 11
	X86FeatureNX       Feature = 6*32 + 20
	X86FeatureMMXEXT   Feature = 6*32 + 22
	X86FeatureFXSR_OPT Feature = 6*32 + 25
	X86FeatureGBPAGES  Feature = 6*32 + 26
	X86FeatureRDTSCP   Feature = 6*32 + 27
	X86FeatureLM       Feature = 6*32 + 29
	X86Feature3DNOWEXT Feature = 6*32 + 30
	X86Feature3DNOW    Feature = 6*32 + 31
)

// Block 7 constants are the extended features bits in
// CPUID.(EAX=07H,ECX=0):EDX.
const (
	_ Feature = 7*32 + iota // edx bit 0 is reserved.
	_                       // edx bit 1 is reserved.
	X86FeatureAVX512_4VNNIW
	X86FeatureAVX512_4FMAPS
	X86FeatureFSRM
	_ // edx bit 5 is not used in Linux.
	_ // edx bit 6 is reserved.
	_ // edx bit 7 is reserved.
	X86FeatureAVX512_VP2INTERSECT
	X86FeatureSRBDS_CTRL
	X86FeatureMD_CLEAR
	X86FeatureRTM_ALWAYS_ABORT
	_ // edx bit 12 is reserved.
	X86FeatureTSX_FORCE_ABORT
	X86FeatureSERIALIZE
	X86FeatureHYBRID_CPU
	X86FeatureTSXLDTRK
	_ // edx bit 17 is reserved.
	X86FeaturePCONFIG
	X86FeatureARCH_LBR
	X86FeatureIBT
	_ // edx bit 21 is reserved.
	X86FeatureAMX_BF16
	X86FeatureAVX512_FP16
	X86FeatureAMX_TILE
	X86FeatureAMX_INT8
	X86FeatureSPEC_CTRL
	X86FeatureINTEL_STIBP
	X86FeatureFLUSH_L1D
	X86FeatureARCH_CAPABILITIES
	X86FeatureCORE_CAPABILITIES
	X86FeatureSPEC_CTRL_SSBD
)

// These are the extended floating point state features. They are used to
// enumerate floating point features in XCR0, XSTATE_BV, etc.
const (
	XSAVEFeatureX87         = 1 << 0
	XSAVEFeatureSSE         = 1 << 1
	XSAVEFeatureAVX         = 1 << 2
	XSAVEFeatureBNDREGS     = 1 << 3
	XSAVEFeatureBNDCSR      = 1 << 4
	XSAVEFeatureAVX512op    = 1 << 5
	XSAVEFeatureAVX512zmm0  = 1 << 6
	XSAVEFeatureAVX512zmm16 = 1 << 7
	XSAVEFeaturePKRU        = 1 << 9
)

// allFeatures is the set of allFeatures.
//
// These match names used in arch/x86/kernel/cpu/capflags.c.
var allFeatures = map[Feature]allFeatureInfo{
	// Block 0.
	X86FeatureSSE3:       {"pni", true},
	X86FeaturePCLMULDQ:   {"pclmulqdq", true},
	X86FeatureDTES64:     {"dtes64", true},
	X86FeatureMONITOR:    {"monitor", true},
	X86FeatureDSCPL:      {"ds_cpl", true},
	X86FeatureVMX:        {"vmx", true},
	X86FeatureSMX:        {"smx", true},
	X86FeatureEST:        {"est", true},
	X86FeatureTM2:        {"tm2", true},
	X86FeatureSSSE3:      {"ssse3", true},
	X86FeatureCNXTID:     {"cid", true},
	X86FeatureSDBG:       {"sdbg", true},
	X86FeatureFMA:        {"fma", true},
	X86FeatureCX16:       {"cx16", true},
	X86FeatureXTPR:       {"xtpr", true},
	X86FeaturePDCM:       {"pdcm", true},
	X86FeaturePCID:       {"pcid", true},
	X86FeatureDCA:        {"dca", true},
	X86FeatureSSE4_1:     {"sse4_1", true},
	X86FeatureSSE4_2:     {"sse4_2", true},
	X86FeatureX2APIC:     {"x2apic", true},
	X86FeatureMOVBE:      {"movbe", true},
	X86FeaturePOPCNT:     {"popcnt", true},
	X86FeatureTSCD:       {"tsc_deadline_timer", true},
	X86FeatureAES:        {"aes", true},
	X86FeatureXSAVE:      {"xsave", true},
	X86FeatureAVX:        {"avx", true},
	X86FeatureF16C:       {"f16c", true},
	X86FeatureRDRAND:     {"rdrand", true},
	X86FeatureHypervisor: {"hypervisor", true},
	X86FeatureOSXSAVE:    {"osxsave", false},

	// Block 1.
	X86FeatureFPU:   {"fpu", true},
	X86FeatureVME:   {"vme", true},
	X86FeatureDE:    {"de", true},
	X86FeaturePSE:   {"pse", true},
	X86FeatureTSC:   {"tsc", true},
	X86FeatureMSR:   {"msr", true},
	X86FeaturePAE:   {"pae", true},
	X86FeatureMCE:   {"mce", true},
	X86FeatureCX8:   {"cx8", true},
	X86FeatureAPIC:  {"apic", true},
	X86FeatureSEP:   {"sep", true},
	X86FeatureMTRR:  {"mtrr", true},
	X86FeaturePGE:   {"pge", true},
	X86FeatureMCA:   {"mca", true},
	X86FeatureCMOV:  {"cmov", true},
	X86FeaturePAT:   {"pat", true},
	X86FeaturePSE36: {"pse36", true},
	X86FeaturePSN:   {"pn", true},
	X86FeatureCLFSH: {"clflush", true},
	X86FeatureDS:    {"dts", true},
	X86FeatureACPI:  {"acpi", true},
	X86FeatureMMX:   {"mmx", true},
	X86FeatureFXSR:  {"fxsr", true},
	X86FeatureSSE:   {"sse", true},
	X86FeatureSSE2:  {"sse2", true},
	X86FeatureSS:    {"ss", true},
	X86FeatureHTT:   {"ht", true},
	X86FeatureTM:    {"tm", true},
	X86FeatureIA64:  {"ia64", true},
	X86FeaturePBE:   {"pbe", true},

	// Block 2.
	X86FeatureFSGSBase:        {"fsgsbase", true},
	X86FeatureTSC_ADJUST:      {"tsc_adjust", true},
	X86FeatureBMI1:            {"bmi1", true},
	X86FeatureHLE:             {"hle", true},
	X86FeatureAVX2:            {"avx2", true},
	X86FeatureSMEP:            {"smep", true},
	X86FeatureBMI2:            {"bmi2", true},
	X86FeatureERMS:            {"erms", true},
	X86FeatureINVPCID:         {"invpcid", true},
	X86FeatureRTM:             {"rtm", true},
	X86FeatureCQM:             {"cqm", true},
	X86FeatureMPX:             {"mpx", true},
	X86FeatureRDT:             {"rdt_a", true},
	X86FeatureAVX512F:         {"avx512f", true},
	X86FeatureAVX512DQ:        {"avx512dq", true},
	X86FeatureRDSEED:          {"rdseed", true},
	X86FeatureADX:             {"adx", true},
	X86FeatureSMAP:            {"smap", true},
	X86FeatureCLWB:            {"clwb", true},
	X86FeatureAVX512PF:        {"avx512pf", true},
	X86FeatureAVX512ER:        {"avx512er", true},
	X86FeatureAVX512CD:        {"avx512cd", true},
	X86FeatureSHA:             {"sha_ni", true},
	X86FeatureAVX512BW:        {"avx512bw", true},
	X86FeatureAVX512VL:        {"avx512vl", true},
	X86FeatureFDP_EXCPTN_ONLY: {"fdp_excptn_only", false},
	X86FeatureFPCSDS:          {"fpcsds", false},
	X86FeatureIPT:             {"ipt", false},
	X86FeatureCLFLUSHOPT:      {"clfushopt", false},

	// Block 3.
	X86FeatureAVX512VBMI:       {"avx512vbmi", true},
	X86FeatureUMIP:             {"umip", true},
	X86FeaturePKU:              {"pku", true},
	X86FeatureOSPKE:            {"ospke", true},
	X86FeatureWAITPKG:          {"waitpkg", true},
	X86FeatureAVX512_VBMI2:     {"avx512_vbmi2", true},
	X86FeatureGFNI:             {"gfni", true},
	X86FeatureCET_SS:           {"cet_ss", false},
	X86FeatureVAES:             {"vaes", true},
	X86FeatureVPCLMULQDQ:       {"vpclmulqdq", true},
	X86FeatureAVX512_VNNI:      {"avx512_vnni", true},
	X86FeatureAVX512_BITALG:    {"avx512_bitalg", true},
	X86FeatureTME:              {"tme", true},
	X86FeatureAVX512_VPOPCNTDQ: {"avx512_vpopcntdq", true},
	X86FeatureLA57:             {"la57", true},
	X86FeatureRDPID:            {"rdpid", true},
	X86FeatureCLDEMOTE:         {"cldemote", true},
	X86FeatureMOVDIRI:          {"movdiri", true},
	X86FeatureMOVDIR64B:        {"movdir64b", true},
	X86FeaturePREFETCHWT1:      {"prefetchwt1", false},

	// Block 4.
	X86FeatureXSAVEOPT: {"xsaveopt", true},
	X86FeatureXSAVEC:   {"xsavec", true},
	X86FeatureXGETBV1:  {"xgetbv1", true},
	X86FeatureXSAVES:   {"xsaves", true},

	// Block 5.
	X86FeatureLAHF64:       {"lahf_lm", true}, // LAHF/SAHF in long mode.
	X86FeatureCMP_LEGACY:   {"cmp_legacy", true},
	X86FeatureSVM:          {"svm", true},
	X86FeatureEXTAPIC:      {"extapic", true},
	X86FeatureCR8_LEGACY:   {"cr8_legacy", true},
	X86FeatureLZCNT:        {"abm", true}, // Advanced bit manipulation.
	X86FeatureSSE4A:        {"sse4a", true},
	X86FeatureMISALIGNSSE:  {"misalignsse", true},
	X86FeaturePREFETCHW:    {"3dnowprefetch", true},
	X86FeatureOSVW:         {"osvw", true},
	X86FeatureIBS:          {"ibs", true},
	X86FeatureXOP:          {"xop", true},
	X86FeatureSKINIT:       {"skinit", true},
	X86FeatureWDT:          {"wdt", true},
	X86FeatureLWP:          {"lwp", true},
	X86FeatureFMA4:         {"fma4", true},
	X86FeatureTCE:          {"tce", true},
	X86FeatureTBM:          {"tbm", true},
	X86FeatureTOPOLOGY:     {"topoext", true},
	X86FeaturePERFCTR_CORE: {"perfctr_core", true},
	X86FeaturePERFCTR_NB:   {"perfctr_nb", true},
	X86FeatureBPEXT:        {"bpext", true},
	X86FeaturePERFCTR_TSC:  {"ptsc", true},
	X86FeaturePERFCTR_LLC:  {"perfctr_llc", true},
	X86FeatureMWAITX:       {"mwaitx", true},
	X86FeatureADMSKEXTN:    {"ad_mask_extn", false},

	// Block 6.
	X86FeatureSYSCALL:  {"syscall", true},
	X86FeatureNX:       {"nx", true},
	X86FeatureMMXEXT:   {"mmxext", true},
	X86FeatureFXSR_OPT: {"fxsr_opt", true},
	X86FeatureGBPAGES:  {"pdpe1gb", true},
	X86FeatureRDTSCP:   {"rdtscp", true},
	X86FeatureLM:       {"lm", true},
	X86Feature3DNOWEXT: {"3dnowext", true},
	X86Feature3DNOW:    {"3dnow", true},

	// Block 7.
	X86FeatureAVX512_4VNNIW:       {"avx512_4vnniw", true},
	X86FeatureAVX512_4FMAPS:       {"avx512_4fmaps", true},
	X86FeatureFSRM:                {"fsrm", true},
	X86FeatureAVX512_VP2INTERSECT: {"avx512_vp2intersect", true},
	X86FeatureSRBDS_CTRL:          {"srbds_ctrl", false},
	X86FeatureMD_CLEAR:            {"md_clear", true},
	X86FeatureRTM_ALWAYS_ABORT:    {"rtm_always_abort", false},
	X86FeatureTSX_FORCE_ABORT:     {"tsx_force_abort", false},
	X86FeatureSERIALIZE:           {"serialize", true},
	X86FeatureHYBRID_CPU:          {"hybrid_cpu", false},
	X86FeatureTSXLDTRK:            {"tsxldtrk", true},
	X86FeaturePCONFIG:             {"pconfig", true},
	X86FeatureARCH_LBR:            {"arch_lbr", true},
	X86FeatureIBT:                 {"ibt", true},
	X86FeatureAMX_BF16:            {"amx_bf16", true},
	X86FeatureAVX512_FP16:         {"avx512_fp16", true},
	X86FeatureAMX_TILE:            {"amx_tile", true},
	X86FeatureAMX_INT8:            {"amx_int8", true},
	X86FeatureSPEC_CTRL:           {"spec_ctrl", false},
	X86FeatureINTEL_STIBP:         {"intel_stibp", false},
	X86FeatureFLUSH_L1D:           {"flush_l1d", true},
	X86FeatureARCH_CAPABILITIES:   {"arch_capabilities", true},
	X86FeatureCORE_CAPABILITIES:   {"core_capabilities", false},
	X86FeatureSPEC_CTRL_SSBD:      {"spec_ctrl_ssbd", false},
}

// linuxBlockOrder defines the order in which linux organizes the feature
// blocks. Linux also tracks feature bits in 32-bit blocks, but in an order
// which doesn't match well here, so for the /proc/cpuinfo generation we simply
// re-map the blocks to Linux's ordering and then go through the bits in each
// block.
var linuxBlockOrder = []block{1, 6, 0, 5, 2, 4, 3, 7}

func archFlagOrder(fn func(Feature)) {
	for _, b := range linuxBlockOrder {
		for i := 0; i < blockSize; i++ {
			f := featureID(b, i)
			if _, ok := allFeatures[f]; ok {
				fn(f)
			}
		}
	}
}
