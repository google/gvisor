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

#include "textflag.h"

// VCPU_CPU is the location of the CPU in the vCPU struct.
//
// This is guaranteed to be zero.
#define VCPU_CPU 0x0

// CPU_SELF is the self reference in ring0's percpu.
//
// This is guaranteed to be zero.
#define CPU_SELF 0x0

// Context offsets.
//
// Only limited use of the context is done in the assembly stub below, most is
// done in the Go handlers.
#define SIGINFO_SIGNO 0x0
#define SIGINFO_CODE 0x8
#define CONTEXT_PC  0x1B8
#define CONTEXT_R0 0xB8

#define SYS_MMAP 222

// getTLS returns the value of TPIDR_EL0 register.
TEXT ·getTLS(SB),NOSPLIT,$0-8
	MRS TPIDR_EL0, R1
	MOVD R1, value+0(FP)
	RET

// setTLS writes the TPIDR_EL0 value.
TEXT ·setTLS(SB),NOSPLIT,$0-8
	MOVD value+0(FP), R1
	MSR R1, TPIDR_EL0
	RET

// See bluepill.go.
TEXT ·bluepill(SB),NOSPLIT,$0
begin:
	MOVD	c+0(FP), R8
	MOVD	$VCPU_CPU(R8), R9
	ORR	$0xffff000000000000, R9, R9
	// Trigger sigill.
	// In ring0.Start(), the value of R8 will be stored into tpidr_el1.
	// When the context was loaded into vcpu successfully,
	// we will check if the value of R10 and R9 are the same.
	WORD	$0xd538d08a // MRS TPIDR_EL1, R10
check_vcpu:
	CMP	R10, R9
	BEQ	right_vCPU
wrong_vcpu:
	CALL	·redpill(SB)
	B	begin
right_vCPU:
	RET

// sighandler: see bluepill.go for documentation.
//
// The arguments are the following:
//
// 	R0 - The signal number.
// 	R1 - Pointer to siginfo_t structure.
// 	R2 - Pointer to ucontext structure.
//
TEXT ·sighandler(SB),NOSPLIT,$0
	// si_signo should be sigill.
	MOVD	SIGINFO_SIGNO(R1), R7
	CMPW	$4, R7
	BNE	fallback

	MOVD	CONTEXT_PC(R2), R7
	CMPW	$0, R7
	BEQ	fallback

	MOVD	R2, 8(RSP)
	BL	·bluepillHandler(SB)   // Call the handler.

	RET

fallback:
	// Jump to the previous signal handler.
	MOVD	·savedHandler(SB), R7
	B	(R7)

// func addrOfSighandler() uintptr
TEXT ·addrOfSighandler(SB), $0-8
	MOVD	$·sighandler(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// The arguments are the following:
//
// 	R0 - The signal number.
// 	R1 - Pointer to siginfo_t structure.
// 	R2 - Pointer to ucontext structure.
//
TEXT ·sigsysHandler(SB),NOSPLIT,$0
	// si_code should be SYS_SECCOMP.
	MOVD	SIGINFO_CODE(R1), R7
	CMPW	$1, R7
	BNE	fallback

	CMPW	$SYS_MMAP, R8
	BNE	fallback

	MOVD	R2, 8(RSP)
	BL	·seccompMmapHandler(SB)   // Call the handler.

	RET

fallback:
	// Jump to the previous signal handler.
	MOVD	·savedHandler(SB), R7
	B	(R7)

// func addrOfSighandler() uintptr
TEXT ·addrOfSigsysHandler(SB), $0-8
	MOVD	$·sigsysHandler(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// dieTrampoline: see bluepill.go, bluepill_arm64_unsafe.go for documentation.
TEXT ·dieTrampoline(SB),NOSPLIT,$0
	// R0: Fake the old PC as caller
	// R1: First argument (vCPU)
	MOVD.P R1, 8(RSP) // R1: First argument (vCPU)
	MOVD.P R0, 8(RSP) // R0: Fake the old PC as caller
	B ·dieHandler(SB)

// func addrOfDieTrampoline() uintptr
TEXT ·addrOfDieTrampoline(SB), $0-8
	MOVD	$·dieTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// currentEL returns the current exception level.
TEXT ·currentEL(SB),NOSPLIT,$0-8
	MRS CurrentEL, R1
	UBFX $2, R1, $2, R1
	MOVD R1, ret+0(FP)
	RET

// func checkPAC() bool
TEXT ·checkPAC(SB),NOSPLIT,$0-1
	MOVD	R30, R0			// Save LR
	WORD	$0xd503233f		// PACIASP (signs R30)
	CMP	R0, R30
	MOVD	$0, R1
	BEQ	same
	MOVD	$1, R1
same:
	MOVD	R0, R30			// Restore LR
	MOVB	R1, ret+0(FP)
	RET

// func flushICache(addr, length uintptr)
// Cleans D-cache to PoU and invalidates I-cache to PoU for [addr, addr+length),
// using the line sizes reported by CTR_EL0.
TEXT ·flushICache(SB),NOSPLIT,$0-16
	MOVD	addr+0(FP), R0
	MOVD	length+8(FP), R1
	ADD	R0, R1, R1		// R1 = end
	MRS	CTR_EL0, R3

	// D-cache line size is 4 << CTR_EL0.DminLine (bits [19:16]).
	UBFX	$16, R3, $4, R4
	MOVD	$4, R5
	LSL	R4, R5, R4		// R4 = 4 << DminLine
	SUB	$1, R4, R5
	BIC	R5, R0, R2		// R2 = addr rounded down to a line
dc_loop:
	CMP	R1, R2
	BHS	dc_done
	WORD	$0xd50b7b22	// DC CVAU, R2
	ADD	R4, R2, R2
	B	dc_loop
dc_done:
	DSB	$11		// DSB ISH

	// I-cache line size is 4 << CTR_EL0.IminLine (bits [3:0]).
	AND	$15, R3, R4
	MOVD	$4, R5
	LSL	R4, R5, R4		// R4 = 4 << IminLine
	SUB	$1, R4, R5
	BIC	R5, R0, R2		// R2 = addr rounded down to a line
ic_loop:
	CMP	R1, R2
	BHS	ic_done
	WORD	$0xd50b7522	// IC IVAU, R2
	ADD	R4, R2, R2
	B	ic_loop
ic_done:
	DSB	$11		// DSB ISH
	ISB	$15		// ISB SY
	RET

