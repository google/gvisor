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
#define CONTEXT_PC  0xB0
#define CONTEXT_A7 0x138

#define SYS_MMAP 222

// See bluepill.go.
TEXT ·bluepill(SB),NOSPLIT,$0
begin:
	MOV	arg+0(FP), A1
	MOV	$VCPU_CPU(A1), A2
	//ORI	$0xffff800000000000, A2
	LUI	$-0x80000, T0
	SLLI	$0x10, T0
	OR	T0, A2
	// Trigger SIGILL
	WORD	$0x140026f3 // csrr a3, sscratch
check_vcpu:
	BEQ	A2, A3, right_vcpu
wrong_vcpu:
	CALL	·redpill(SB)
	JMP	begin
right_vcpu:
	RET

// sighandler: see bluepill.go for documentation.
//
// The arguments are the following:
//
// 	A0 - The signal number.
// 	A1 - Pointer to siginfo_t structure.
// 	A2 - Pointer to ucontext structure.
//
TEXT ·sighandler(SB),NOSPLIT,$0
	MOV	SIGINFO_SIGNO(A1), T1
	MOV	$4, T2
	BNE	T1, T2, fallback

	MOV	CONTEXT_PC(A2), T1
	BEQ	ZERO, T1, fallback

	MOV	A2, 8(SP)
	CALL	·bluepillHandler(SB)

	RET

fallback:
	// Jump to the previous signal handler.
	MOV	·savedHandler(SB), T1
	JMP	(T1)

// func addrOfSighandler() uintptr
TEXT ·addrOfSighandler(SB), $0-8
	MOV	$·sighandler(SB), A0
	MOV	A0, ret+0(FP)
	RET

// The arguments are the following:
//
// 	A0 - The signal number.
// 	A1 - Pointer to siginfo_t structure.
// 	A2 - Pointer to ucontext structure.
//
TEXT ·sigsysHandler(SB),NOSPLIT,$0
	// si_code should be SYS_SECCOMP.
	MOV	SIGINFO_CODE(A1), T1
	MOV	$1, T2
	BNE	T1, T2, fallback

	MOV	CONTEXT_A7(A2), T1
	MOV	$SYS_MMAP, T2
	BNE	T1, T2, fallback

	MOV	A2, 8(SP)
	CALL	·seccompMmapHandler(SB)   // Call the handler.

	RET

fallback:
	// Jump to the previous signal handler.
	MOV	·savedHandler(SB), T1
	JMP	(T1)

// func addrOfSighandler() uintptr
TEXT ·addrOfSigsysHandler(SB), $0-8
	MOV	$·sigsysHandler(SB), A0
	MOV	A0, ret+0(FP)
	RET

// dieTrampoline: see bluepill.go, bluepill_riscv64.go for documentation.
TEXT ·dieTrampoline(SB),NOSPLIT,$0
	// A0: Fake the old PC as caller
	// A1: First argument (vCPU)
	MOV	A1, 8(SP) // A1: First argument (vCPU)
	MOV	A0, 16(SP) // A0: Fake the old PC as caller
	JMP ·dieHandler(SB)

// func addrOfDieTrampoline() uintptr
TEXT ·addrOfDieTrampoline(SB), $0-8
	MOV	$·dieTrampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET
