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
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// ARM64 doesn't have a 'cpuid' equivalent, which means it have no architected
// discovery mechanism for hardware features available to userspace code at EL0.
// The kernel exposes the presence of these features to userspace through a set
// of flags(HWCAP/HWCAP2) bits, exposed in the auxilliary vector.
// Ref Documentation/arm64/elf_hwcaps.rst for more info.
//
// Currently, only the HWCAP bits are supported.

const (
	// ARM64FeatureFP indicates support for single and double precision
	// float point types.
	ARM64FeatureFP Feature = iota

	// ARM64FeatureASIMD indicates support for Advanced SIMD with single
	// and double precision float point arithmetic.
	ARM64FeatureASIMD

	// ARM64FeatureEVTSTRM indicates support for the generic timer
	// configured to generate events at a frequency of approximately
	// 100KHz.
	ARM64FeatureEVTSTRM

	// ARM64FeatureAES indicates support for AES instructions
	// (AESE/AESD/AESMC/AESIMC).
	ARM64FeatureAES

	// ARM64FeaturePMULL indicates support for AES instructions
	// (PMULL/PMULL2).
	ARM64FeaturePMULL

	// ARM64FeatureSHA1 indicates support for SHA1 instructions
	// (SHA1C/SHA1P/SHA1M etc).
	ARM64FeatureSHA1

	// ARM64FeatureSHA2 indicates support for SHA2 instructions
	// (SHA256H/SHA256H2/SHA256SU0 etc).
	ARM64FeatureSHA2

	// ARM64FeatureCRC32 indicates support for CRC32 instructions
	// (CRC32B/CRC32H/CRC32W etc).
	ARM64FeatureCRC32

	// ARM64FeatureATOMICS indicates support for atomic instructions
	// (LDADD/LDCLR/LDEOR/LDSET etc).
	ARM64FeatureATOMICS

	// ARM64FeatureFPHP indicates support for half precision float point
	// arithmetic.
	ARM64FeatureFPHP

	// ARM64FeatureASIMDHP indicates support for ASIMD with half precision
	// float point arithmetic.
	ARM64FeatureASIMDHP

	// ARM64FeatureCPUID indicates support for EL0 access to certain ID
	// registers is available.
	ARM64FeatureCPUID

	// ARM64FeatureASIMDRDM indicates support for SQRDMLAH and SQRDMLSH
	// instructions.
	ARM64FeatureASIMDRDM

	// ARM64FeatureJSCVT indicates support for the FJCVTZS instruction.
	ARM64FeatureJSCVT

	// ARM64FeatureFCMA indicates support for the FCMLA and FCADD
	// instructions.
	ARM64FeatureFCMA

	// ARM64FeatureLRCPC indicates support for the LDAPRB/LDAPRH/LDAPR
	// instructions.
	ARM64FeatureLRCPC

	// ARM64FeatureDCPOP indicates support for DC instruction (DC CVAP).
	ARM64FeatureDCPOP

	// ARM64FeatureSHA3 indicates support for SHA3 instructions
	// (EOR3/RAX1/XAR/BCAX).
	ARM64FeatureSHA3

	// ARM64FeatureSM3 indicates support for SM3 instructions
	// (SM3SS1/SM3TT1A/SM3TT1B).
	ARM64FeatureSM3

	// ARM64FeatureSM4 indicates support for SM4 instructions
	// (SM4E/SM4EKEY).
	ARM64FeatureSM4

	// ARM64FeatureASIMDDP indicates support for dot product instructions
	// (UDOT/SDOT).
	ARM64FeatureASIMDDP

	// ARM64FeatureSHA512 indicates support for SHA2 instructions
	// (SHA512H/SHA512H2/SHA512SU0).
	ARM64FeatureSHA512

	// ARM64FeatureSVE indicates support for Scalable Vector Extension.
	ARM64FeatureSVE

	// ARM64FeatureASIMDFHM indicates support for FMLAL and FMLSL
	// instructions.
	ARM64FeatureASIMDFHM
)

// ELF auxiliary vector tags
const (
	_AT_NULL   = 0  // End of vector
	_AT_HWCAP  = 16 // hardware capability bit vector
	_AT_HWCAP2 = 26 // hardware capability bit vector 2
)

// These should not be changed after they are initialized.
var hwCap uint

// To make emulation of /proc/cpuinfo easy, these names match the names of the
// basic features in Linux defined in arch/arm64/kernel/cpuinfo.c.
var arm64FeatureStrings = map[Feature]string{
	ARM64FeatureFP:       "fp",
	ARM64FeatureASIMD:    "asimd",
	ARM64FeatureEVTSTRM:  "evtstrm",
	ARM64FeatureAES:      "aes",
	ARM64FeaturePMULL:    "pmull",
	ARM64FeatureSHA1:     "sha1",
	ARM64FeatureSHA2:     "sha2",
	ARM64FeatureCRC32:    "crc32",
	ARM64FeatureATOMICS:  "atomics",
	ARM64FeatureFPHP:     "fphp",
	ARM64FeatureASIMDHP:  "asimdhp",
	ARM64FeatureCPUID:    "cpuid",
	ARM64FeatureASIMDRDM: "asimdrdm",
	ARM64FeatureJSCVT:    "jscvt",
	ARM64FeatureFCMA:     "fcma",
	ARM64FeatureLRCPC:    "lrcpc",
	ARM64FeatureDCPOP:    "dcpop",
	ARM64FeatureSHA3:     "sha3",
	ARM64FeatureSM3:      "sm3",
	ARM64FeatureSM4:      "sm4",
	ARM64FeatureASIMDDP:  "asimddp",
	ARM64FeatureSHA512:   "sha512",
	ARM64FeatureSVE:      "sve",
	ARM64FeatureASIMDFHM: "asimdfhm",
}

var (
	cpuFreqMHz float64
	cpuImplHex uint64
	cpuArchDec uint64
	cpuVarHex  uint64
	cpuPartHex uint64
	cpuRevDec  uint64
)

// arm64FeaturesFromString includes features from arm64FeatureStrings.
var arm64FeaturesFromString = make(map[string]Feature)

// FeatureFromString returns the Feature associated with the given feature
// string plus a bool to indicate if it could find the feature.
func FeatureFromString(s string) (Feature, bool) {
	f, b := arm64FeaturesFromString[s]
	return f, b
}

// String implements fmt.Stringer.
func (f Feature) String() string {
	if s := f.flagString(); s != "" {
		return s
	}

	return fmt.Sprintf("<cpuflag %d>", f)
}

func (f Feature) flagString() string {
	if s, ok := arm64FeatureStrings[f]; ok {
		return s
	}

	return ""
}

// FeatureSet is a set of Features for a CPU.
//
// +stateify savable
type FeatureSet struct {
	// Set is the set of features that are enabled in this FeatureSet.
	Set map[Feature]bool

	// CPUImplementer is part of the processor signature.
	CPUImplementer uint8

	// CPUArchitecture is part of the processor signature.
	CPUArchitecture uint8

	// CPUVariant is part of the processor signature.
	CPUVariant uint8

	// CPUPartnum is part of the processor signature.
	CPUPartnum uint16

	// CPURevision is part of the processor signature.
	CPURevision uint8
}

// CheckHostCompatible returns nil if fs is a subset of the host feature set.
// Noop on arm64.
func (fs *FeatureSet) CheckHostCompatible() error {
	return nil
}

// ExtendedStateSize returns the number of bytes needed to save the "extended
// state" for this processor and the boundary it must be aligned to. Extended
// state includes floating point(NEON) registers, and other cpu state that's not
// associated with the normal task context.
func (fs *FeatureSet) ExtendedStateSize() (size, align uint) {
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

// HasFeature tests whether or not a feature is in the given feature set.
func (fs *FeatureSet) HasFeature(feature Feature) bool {
	return fs.Set[feature]
}

// UseXsave returns true if 'fs' supports the "xsave" instruction.
//
// Irrelevant on arm64.
func (fs *FeatureSet) UseXsave() bool {
	return false
}

// FlagsString prints out supported CPU "flags" field in /proc/cpuinfo.
func (fs *FeatureSet) FlagsString() string {
	var s []string
	for f := range arm64FeatureStrings {
		if fs.Set[f] {
			if fstr := f.flagString(); fstr != "" {
				s = append(s, fstr)
			}
		}
	}
	return strings.Join(s, " ")
}

// WriteCPUInfoTo is to generate a section of one cpu in /proc/cpuinfo. This is
// a minimal /proc/cpuinfo, and the bogomips field is simply made up.
func (fs FeatureSet) WriteCPUInfoTo(cpu uint, b *bytes.Buffer) {
	fmt.Fprintf(b, "processor\t: %d\n", cpu)
	fmt.Fprintf(b, "BogoMIPS\t: %.02f\n", cpuFreqMHz) // It's bogus anyway.
	fmt.Fprintf(b, "Features\t\t: %s\n", fs.FlagsString())
	fmt.Fprintf(b, "CPU implementer\t: 0x%x\n", cpuImplHex)
	fmt.Fprintf(b, "CPU architecture\t: %d\n", cpuArchDec)
	fmt.Fprintf(b, "CPU variant\t: 0x%x\n", cpuVarHex)
	fmt.Fprintf(b, "CPU part\t: 0x%x\n", cpuPartHex)
	fmt.Fprintf(b, "CPU revision\t: %d\n", cpuRevDec)
	fmt.Fprintln(b, "") // The /proc/cpuinfo file ends with an extra newline.
}

// HostFeatureSet uses hwCap to get host values and construct a feature set
// that matches that of the host machine.
func HostFeatureSet() *FeatureSet {
	s := make(map[Feature]bool)

	for f := range arm64FeatureStrings {
		if hwCap&(1<<f) != 0 {
			s[f] = true
		}
	}

	return &FeatureSet{
		Set:             s,
		CPUImplementer:  uint8(cpuImplHex),
		CPUArchitecture: uint8(cpuArchDec),
		CPUVariant:      uint8(cpuVarHex),
		CPUPartnum:      uint16(cpuPartHex),
		CPURevision:     uint8(cpuRevDec),
	}
}

// Reads bogomips from host /proc/cpuinfo. Must run before syscall filter
// installation. This value is used to create the fake /proc/cpuinfo from a
// FeatureSet.
func initCPUInfo() {
	cpuinfob, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		// Leave it as 0. The standalone VDSO bails out in the same way.
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	cpuinfo := string(cpuinfob)

	// We get the value straight from host /proc/cpuinfo.
	for _, line := range strings.Split(cpuinfo, "\n") {
		switch {
		case strings.Contains(line, "BogoMIPS"):
			{
				splitMHz := strings.Split(line, ":")
				if len(splitMHz) < 2 {
					log.Warningf("Could not read /proc/cpuinfo: malformed BogoMIPS")
					break
				}

				// If there was a problem, leave cpuFreqMHz as 0.
				var err error
				cpuFreqMHz, err = strconv.ParseFloat(strings.TrimSpace(splitMHz[1]), 64)
				if err != nil {
					log.Warningf("Could not parse BogoMIPS value %v: %v", splitMHz[1], err)
					cpuFreqMHz = 0
				}
			}
		case strings.Contains(line, "CPU implementer"):
			{
				splitImpl := strings.Split(line, ":")
				if len(splitImpl) < 2 {
					log.Warningf("Could not read /proc/cpuinfo: malformed CPU implementer")
					break
				}

				// If there was a problem, leave cpuImplHex as 0.
				var err error
				cpuImplHex, err = strconv.ParseUint(strings.TrimSpace(splitImpl[1]), 0, 64)
				if err != nil {
					log.Warningf("Could not parse CPU implementer value %v: %v", splitImpl[1], err)
					cpuImplHex = 0
				}
			}
		case strings.Contains(line, "CPU architecture"):
			{
				splitArch := strings.Split(line, ":")
				if len(splitArch) < 2 {
					log.Warningf("Could not read /proc/cpuinfo: malformed CPU architecture")
					break
				}

				// If there was a problem, leave cpuArchDec as 0.
				var err error
				cpuArchDec, err = strconv.ParseUint(strings.TrimSpace(splitArch[1]), 0, 64)
				if err != nil {
					log.Warningf("Could not parse CPU architecture value %v: %v", splitArch[1], err)
					cpuArchDec = 0
				}
			}
		case strings.Contains(line, "CPU variant"):
			{
				splitVar := strings.Split(line, ":")
				if len(splitVar) < 2 {
					log.Warningf("Could not read /proc/cpuinfo: malformed CPU variant")
					break
				}

				// If there was a problem, leave cpuVarHex as 0.
				var err error
				cpuVarHex, err = strconv.ParseUint(strings.TrimSpace(splitVar[1]), 0, 64)
				if err != nil {
					log.Warningf("Could not parse CPU variant value %v: %v", splitVar[1], err)
					cpuVarHex = 0
				}
			}
		case strings.Contains(line, "CPU part"):
			{
				splitPart := strings.Split(line, ":")
				if len(splitPart) < 2 {
					log.Warningf("Could not read /proc/cpuinfo: malformed CPU part")
					break
				}

				// If there was a problem, leave cpuPartHex as 0.
				var err error
				cpuPartHex, err = strconv.ParseUint(strings.TrimSpace(splitPart[1]), 0, 64)
				if err != nil {
					log.Warningf("Could not parse CPU part value %v: %v", splitPart[1], err)
					cpuPartHex = 0
				}
			}
		case strings.Contains(line, "CPU revision"):
			{
				splitRev := strings.Split(line, ":")
				if len(splitRev) < 2 {
					log.Warningf("Could not read /proc/cpuinfo: malformed CPU revision")
					break
				}

				// If there was a problem, leave cpuRevDec as 0.
				var err error
				cpuRevDec, err = strconv.ParseUint(strings.TrimSpace(splitRev[1]), 0, 64)
				if err != nil {
					log.Warningf("Could not parse CPU revision value %v: %v", splitRev[1], err)
					cpuRevDec = 0
				}
			}
		}
	}
}

// The auxiliary vector of a process on the Linux system can be read
// from /proc/self/auxv, and tags and values are stored as 8-bytes
// decimal key-value pairs on the 64-bit system.
//
// $ od -t d8 /proc/self/auxv
//  0000000                   33      140734615224320
//  0000020                   16           3219913727
//  0000040                    6                 4096
//  0000060                   17                  100
//  0000100                    3       94665627353152
//  0000120                    4                   56
//  0000140                    5                    9
//  0000160                    7      140425502162944
//  0000200                    8                    0
//  0000220                    9       94665627365760
//  0000240                   11                 1000
//  0000260                   12                 1000
//  0000300                   13                 1000
//  0000320                   14                 1000
//  0000340                   23                    0
//  0000360                   25      140734614619513
//  0000400                   26                    0
//  0000420                   31      140734614626284
//  0000440                   15      140734614619529
//  0000460                    0                    0
func initHwCap() {
	auxv, err := ioutil.ReadFile("/proc/self/auxv")
	if err != nil {
		log.Warningf("Could not read /proc/self/auxv: %v", err)
		return
	}

	l := len(auxv) / 16
	for i := 0; i < l; i++ {
		tag := binary.LittleEndian.Uint64(auxv[i*16:])
		val := binary.LittleEndian.Uint64(auxv[(i*16 + 8):])
		if tag == _AT_HWCAP {
			hwCap = uint(val)
			break
		}
	}
}

func initFeaturesFromString() {
	for f, s := range arm64FeatureStrings {
		arm64FeaturesFromString[s] = f
	}
}

func init() {
	initCPUInfo()
	initHwCap()
	initFeaturesFromString()
}
