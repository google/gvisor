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

// +build arm64

#include "funcdata.h"
#include "textflag.h"

#define ID_AA64MMFR0_ASIDBITS_SHIFT 4
#define ID_AA64MMFR0_ASIDBITS_16 2
#define TCR_EL1_AS_BIT 36

// GetASIDBits return the system ASID bits, 8 or 16 bits.
//
// func GetASIDBits() uint8
TEXT ·GetASIDBits(SB),NOSPLIT,$0-1
	// First, check whether 16bits ASID is supported.
	// ID_AA64MMFR0_EL1.ASIDBITS[7:4] == 0010.
	WORD $0xd5380700    // MRS ID_AA64MMFR0_EL1, R0
	UBFX $ID_AA64MMFR0_ASIDBITS_SHIFT, R0, $4, R0
	CMPW $ID_AA64MMFR0_ASIDBITS_16, R0
	BNE bits_8

	// Second, check whether 16bits ASID is enabled.
	// TCR_EL1.AS[36] == 1.
	WORD $0xd5382040    // MRS TCR_EL1, R0
	TBZ  $TCR_EL1_AS_BIT, R0, bits_8
	MOVD $16, R0
	B done
bits_8:
	MOVD $8, R0
done:
	MOVB R0, ret+0(FP)
	RET
