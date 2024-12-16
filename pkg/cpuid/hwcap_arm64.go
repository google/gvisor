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

//go:build arm64
// +build arm64

package cpuid

// See arch/arm64/include/uapi/asm/hwcap.h
const (
	// HWCAP flags for AT_HWCAP.
	HWCAP_FP       = 1 << 0
	HWCAP_ASIMD    = 1 << 1
	HWCAP_EVTSTRM  = 1 << 2
	HWCAP_AES      = 1 << 3
	HWCAP_PMULL    = 1 << 4
	HWCAP_SHA1     = 1 << 5
	HWCAP_SHA2     = 1 << 6
	HWCAP_CRC32    = 1 << 7
	HWCAP_ATOMICS  = 1 << 8
	HWCAP_FPHP     = 1 << 9
	HWCAP_ASIMDHP  = 1 << 10
	HWCAP_CPUID    = 1 << 11
	HWCAP_ASIMDRDM = 1 << 12
	HWCAP_JSCVT    = 1 << 13
	HWCAP_FCMA     = 1 << 14
	HWCAP_LRCPC    = 1 << 15
	HWCAP_DCPOP    = 1 << 16
	HWCAP_SHA3     = 1 << 17
	HWCAP_SM3      = 1 << 18
	HWCAP_SM4      = 1 << 19
	HWCAP_ASIMDDP  = 1 << 20
	HWCAP_SHA512   = 1 << 21
	HWCAP_SVE      = 1 << 22
	HWCAP_ASIMDFHM = 1 << 23
	HWCAP_DIT      = 1 << 24
	HWCAP_USCAT    = 1 << 25
	HWCAP_ILRCPC   = 1 << 26
	HWCAP_FLAGM    = 1 << 27
	HWCAP_SSBS     = 1 << 28
	HWCAP_SB       = 1 << 29
	HWCAP_PACA     = 1 << 30
	HWCAP_PACG     = 1 << 31

	// HWCAP2 flags for AT_HWCAP2.
	HWCAP2_DCPODP     = 1 << 0
	HWCAP2_SVE2       = 1 << 1
	HWCAP2_SVEAES     = 1 << 2
	HWCAP2_SVEPMULL   = 1 << 3
	HWCAP2_SVEBITPERM = 1 << 4
	HWCAP2_SVESHA3    = 1 << 5
	HWCAP2_SVESM4     = 1 << 6
	HWCAP2_FLAGM2     = 1 << 7
	HWCAP2_FRINT      = 1 << 8
	HWCAP2_SVEI8MM    = 1 << 9
	HWCAP2_SVEF32MM   = 1 << 10
	HWCAP2_SVEF64MM   = 1 << 11
	HWCAP2_SVEBF16    = 1 << 12
	HWCAP2_I8MM       = 1 << 13
	HWCAP2_BF16       = 1 << 14
	HWCAP2_DGH        = 1 << 15
	HWCAP2_RNG        = 1 << 16
	HWCAP2_BTI        = 1 << 17
	HWCAP2_MTE        = 1 << 18
	HWCAP2_ECV        = 1 << 19
	HWCAP2_AFP        = 1 << 20
	HWCAP2_RPRES      = 1 << 21
)
