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

#include "funcdata.h"
#include "textflag.h"

TEXT ·LocalFlushTlbAll(SB),NOSPLIT,$0
	DSB $6			// dsb(nshst)
	WORD $0xd508871f	// __tlbi(vmalle1)
	DSB $7			// dsb(nsh)
	ISB $15
	RET

TEXT ·FlushTlbAll(SB),NOSPLIT,$0
	DSB $10			// dsb(ishst)
	WORD $0xd508831f	// __tlbi(vmalle1is)
	DSB $11			// dsb(ish)
	ISB $15
	RET

TEXT ·CPACREL1(SB),NOSPLIT,$0-8
	WORD $0xd5381041 	// MRS CPACR_EL1, R1
	MOVD R1, ret+0(FP)
	RET

TEXT ·GetFPCR(SB),NOSPLIT,$0-8
	WORD $0xd53b4201    	// MRS NZCV, R1
	MOVD R1, ret+0(FP)
	RET

TEXT ·GetFPSR(SB),NOSPLIT,$0-8
	WORD $0xd53b4421   	// MRS FPSR, R1
	MOVD R1, ret+0(FP)
	RET

TEXT ·SetFPCR(SB),NOSPLIT,$0-8
	MOVD addr+0(FP), R1
	WORD $0xd51b4201  	// MSR R1, NZCV
	RET

TEXT ·SetFPSR(SB),NOSPLIT,$0-8
	MOVD addr+0(FP), R1
	WORD $0xd51b4421   	// MSR R1, FPSR
	RET

TEXT ·SaveVRegs(SB),NOSPLIT,$0-8
	MOVD addr+0(FP), R0

	// Skip aarch64_ctx, fpsr, fpcr.
	FMOVD F0, 16*1(R0)
	FMOVD F1, 16*2(R0)
	FMOVD F2, 16*3(R0)
	FMOVD F3, 16*4(R0)
	FMOVD F4, 16*5(R0)
	FMOVD F5, 16*6(R0)
	FMOVD F6, 16*7(R0)
	FMOVD F7, 16*8(R0)
	FMOVD F8, 16*9(R0)
	FMOVD F9, 16*10(R0)
	FMOVD F10, 16*11(R0)
	FMOVD F11, 16*12(R0)
	FMOVD F12, 16*13(R0)
	FMOVD F13, 16*14(R0)
	FMOVD F14, 16*15(R0)
	FMOVD F15, 16*16(R0)
	FMOVD F16, 16*17(R0)
	FMOVD F17, 16*18(R0)
	FMOVD F18, 16*19(R0)
	FMOVD F19, 16*20(R0)
	FMOVD F20, 16*21(R0)
	FMOVD F21, 16*22(R0)
	FMOVD F22, 16*23(R0)
	FMOVD F23, 16*24(R0)
	FMOVD F24, 16*25(R0)
	FMOVD F25, 16*26(R0)
	FMOVD F26, 16*27(R0)
	FMOVD F27, 16*28(R0)
	FMOVD F28, 16*29(R0)
	FMOVD F29, 16*30(R0)
	FMOVD F30, 16*31(R0)
	FMOVD F31, 16*32(R0)
	ISB $15

	RET

TEXT ·LoadVRegs(SB),NOSPLIT,$0-8
	MOVD addr+0(FP), R0

	// Skip aarch64_ctx, fpsr, fpcr.
	FMOVD 16*1(R0), F0
	FMOVD 16*2(R0), F1
	FMOVD 16*3(R0), F2
	FMOVD 16*4(R0), F3
	FMOVD 16*5(R0), F4
	FMOVD 16*6(R0), F5
	FMOVD 16*7(R0), F6
	FMOVD 16*8(R0), F7
	FMOVD 16*9(R0), F8
	FMOVD 16*10(R0), F9
	FMOVD 16*11(R0), F10
	FMOVD 16*12(R0), F11
	FMOVD 16*13(R0), F12
	FMOVD 16*14(R0), F13
	FMOVD 16*15(R0), F14
	FMOVD 16*16(R0), F15
	FMOVD 16*17(R0), F16
	FMOVD 16*18(R0), F17
	FMOVD 16*19(R0), F18
	FMOVD 16*20(R0), F19
	FMOVD 16*21(R0), F20
	FMOVD 16*22(R0), F21
	FMOVD 16*23(R0), F22
	FMOVD 16*24(R0), F23
	FMOVD 16*25(R0), F24
	FMOVD 16*26(R0), F25
	FMOVD 16*27(R0), F26
	FMOVD 16*28(R0), F27
	FMOVD 16*29(R0), F28
	FMOVD 16*30(R0), F29
	FMOVD 16*31(R0), F30
	FMOVD 16*32(R0), F31
	ISB $15

	RET

TEXT ·LoadFloatingPoint(SB),NOSPLIT,$0-8
	MOVD addr+0(FP), R0

	MOVD 0(R0), R1
	MOVD R1, FPSR
	MOVD 8(R0), R1
	MOVD R1, FPCR

	ADD $16, R0, R0

	WORD $0xad400400 	// ldp	q0, q1, [x0]
	WORD $0xad410c02 	// ldp	q2, q3, [x0, #32]
	WORD $0xad421404 	// ldp	q4, q5, [x0, #64]
	WORD $0xad431c06 	// ldp	q6, q7, [x0, #96]
	WORD $0xad442408 	// ldp	q8, q9, [x0, #128]
	WORD $0xad452c0a 	// ldp	q10, q11, [x0, #160]
	WORD $0xad46340c 	// ldp	q12, q13, [x0, #192]
	WORD $0xad473c0e 	// ldp	q14, q15, [x0, #224]
	WORD $0xad484410 	// ldp	q16, q17, [x0, #256]
	WORD $0xad494c12 	// ldp	q18, q19, [x0, #288]
	WORD $0xad4a5414 	// ldp	q20, q21, [x0, #320]
	WORD $0xad4b5c16 	// ldp	q22, q23, [x0, #352]
	WORD $0xad4c6418 	// ldp	q24, q25, [x0, #384]
	WORD $0xad4d6c1a 	// ldp	q26, q27, [x0, #416]
	WORD $0xad4e741c 	// ldp	q28, q29, [x0, #448]
	WORD $0xad4f7c1e 	// ldp	q30, q31, [x0, #480]

	RET

TEXT ·SaveFloatingPoint(SB),NOSPLIT,$0-8
	MOVD addr+0(FP), R0

	MOVD FPSR, R1
	MOVD R1, 0(R0)
	MOVD FPCR, R1
	MOVD R1, 8(R0)

	ADD $16, R0, R0

	WORD $0xad000400       //  stp	q0, q1, [x0]
	WORD $0xad010c02       //  stp	q2, q3, [x0, #32]
	WORD $0xad021404       //  stp	q4, q5, [x0, #64]
	WORD $0xad031c06       //  stp	q6, q7, [x0, #96]
	WORD $0xad042408       //  stp	q8, q9, [x0, #128]
	WORD $0xad052c0a       //  stp	q10, q11, [x0, #160]
	WORD $0xad06340c       //  stp	q12, q13, [x0, #192]
	WORD $0xad073c0e       //  stp	q14, q15, [x0, #224]
	WORD $0xad084410       //  stp	q16, q17, [x0, #256]
	WORD $0xad094c12       //  stp	q18, q19, [x0, #288]
	WORD $0xad0a5414       //  stp	q20, q21, [x0, #320]
	WORD $0xad0b5c16       //  stp	q22, q23, [x0, #352]
	WORD $0xad0c6418       //  stp	q24, q25, [x0, #384]
	WORD $0xad0d6c1a       //  stp	q26, q27, [x0, #416]
	WORD $0xad0e741c       //  stp	q28, q29, [x0, #448]
	WORD $0xad0f7c1e       //  stp	q30, q31, [x0, #480]

	RET
