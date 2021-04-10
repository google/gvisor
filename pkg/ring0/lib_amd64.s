// Copyright 2018 The gVisor Authors.
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

// fxrstor loads floating point state.
//
// The code corresponds to:
//
//     fxrstor64 (%rbx)
//
TEXT ·fxrstor(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), BX
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x0b;
	RET

// xrstor loads floating point state.
//
// The code corresponds to:
//
//     xrstor (%rdi)
//
TEXT ·xrstor(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), DI
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x2f;
	RET

// fxsave saves floating point state.
//
// The code corresponds to:
//
//     fxsave64 (%rbx)
//
TEXT ·fxsave(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), BX
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x03;
	RET

// xsave saves floating point state.
//
// The code corresponds to:
//
//     xsave (%rdi)
//
TEXT ·xsave(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), DI
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x27;
	RET

// xsaveopt saves floating point state.
//
// The code corresponds to:
//
//     xsaveopt (%rdi)
//
TEXT ·xsaveopt(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), DI
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x37;
	RET

// wrfsbase writes to the FS base.
//
// The code corresponds to:
//
// 	wrfsbase %rax
//
TEXT ·wrfsbase(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), AX
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0xd0;
	RET

// wrfsmsr writes to the FSBASE MSR.
//
// The code corresponds to:
//
// 	wrmsr (writes EDX:EAX to the MSR in ECX)
//
TEXT ·wrfsmsr(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), AX
	MOVQ AX, DX
	SHRQ $32, DX
	MOVQ $0xc0000100, CX // MSR_FS_BASE
	BYTE $0x0f; BYTE $0x30;
	RET

// wrgsbase writes to the GS base.
//
// The code corresponds to:
//
// 	wrgsbase %rax
//
TEXT ·wrgsbase(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), AX
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0xd8;
	RET

// wrgsmsr writes to the GSBASE MSR.
//
// See wrfsmsr.
TEXT ·wrgsmsr(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), AX
	MOVQ AX, DX
	SHRQ $32, DX
	MOVQ $0xc0000101, CX     // MSR_GS_BASE
	BYTE $0x0f; BYTE $0x30;  // WRMSR
	RET

// readCR2 reads the current CR2 value.
//
// The code corresponds to:
//
// 	mov %cr2, %rax
//
TEXT ·readCR2(SB),NOSPLIT,$0-8
	BYTE $0x0f; BYTE $0x20; BYTE $0xd0;
	MOVQ AX, ret+0(FP)
	RET

// fninit initializes the floating point unit.
//
// The code corresponds to:
//
// 	fninit
TEXT ·fninit(SB),NOSPLIT,$0
	BYTE $0xdb; BYTE $0xe3;
	RET

// xsetbv writes to an extended control register.
//
// The code corresponds to:
//
// 	xsetbv
//
TEXT ·xsetbv(SB),NOSPLIT,$0-16
	MOVL reg+0(FP), CX
	MOVL value+8(FP), AX
	MOVL value+12(FP), DX
	BYTE $0x0f; BYTE $0x01; BYTE $0xd1;
	RET

// xgetbv reads an extended control register.
//
// The code corresponds to:
//
// 	xgetbv
//
TEXT ·xgetbv(SB),NOSPLIT,$0-16
	MOVL reg+0(FP), CX
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0;
	MOVL AX, ret+8(FP)
	MOVL DX, ret+12(FP)
	RET

// wrmsr writes to a control register.
//
// The code corresponds to:
//
// 	wrmsr
//
TEXT ·wrmsr(SB),NOSPLIT,$0-16
	MOVL reg+0(FP), CX
	MOVL value+8(FP), AX
	MOVL value+12(FP), DX
	BYTE $0x0f; BYTE $0x30;
	RET

// rdmsr reads a control register.
//
// The code corresponds to:
//
// 	rdmsr
//
TEXT ·rdmsr(SB),NOSPLIT,$0-16
	MOVL reg+0(FP), CX
	BYTE $0x0f; BYTE $0x32;
	MOVL AX, ret+8(FP)
	MOVL DX, ret+12(FP)
	RET

// stmxcsr reads the MXCSR control and status register.
TEXT ·stmxcsr(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), SI
	STMXCSR (SI)
	RET

// ldmxcsr writes to the MXCSR control and status register.
TEXT ·ldmxcsr(SB),NOSPLIT,$0-8
	MOVQ addr+0(FP), SI
	LDMXCSR (SI)
	RET
