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

var allFeatures = map[Feature]allFeatureInfo{
	ARM64FeatureFP:       {"fp", true},
	ARM64FeatureASIMD:    {"asimd", true},
	ARM64FeatureEVTSTRM:  {"evtstrm", true},
	ARM64FeatureAES:      {"aes", true},
	ARM64FeaturePMULL:    {"pmull", true},
	ARM64FeatureSHA1:     {"sha1", true},
	ARM64FeatureSHA2:     {"sha2", true},
	ARM64FeatureCRC32:    {"crc32", true},
	ARM64FeatureATOMICS:  {"atomics", true},
	ARM64FeatureFPHP:     {"fphp", true},
	ARM64FeatureASIMDHP:  {"asimdhp", true},
	ARM64FeatureCPUID:    {"cpuid", true},
	ARM64FeatureASIMDRDM: {"asimdrdm", true},
	ARM64FeatureJSCVT:    {"jscvt", true},
	ARM64FeatureFCMA:     {"fcma", true},
	ARM64FeatureLRCPC:    {"lrcpc", true},
	ARM64FeatureDCPOP:    {"dcpop", true},
	ARM64FeatureSHA3:     {"sha3", true},
	ARM64FeatureSM3:      {"sm3", true},
	ARM64FeatureSM4:      {"sm4", true},
	ARM64FeatureASIMDDP:  {"asimddp", true},
	ARM64FeatureSHA512:   {"sha512", true},
	ARM64FeatureSVE:      {"sve", true},
	ARM64FeatureASIMDFHM: {"asimdfhm", true},
}

func archFlagOrder(fn func(Feature)) {
	for i := 0; i < len(allFeatures); i++ {
		fn(Feature(i))
	}
}
