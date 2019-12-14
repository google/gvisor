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
#define CONTEXT_PC  0x1B8
#define CONTEXT_R0 0xB8

// See bluepill.go.
TEXT ·bluepill(SB),NOSPLIT,$0
begin:
	MOVD	vcpu+0(FP), R8
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

// dieTrampoline: see bluepill.go, bluepill_arm64_unsafe.go for documentation.
TEXT ·dieTrampoline(SB),NOSPLIT,$0
	// TODO(gvisor.dev/issue/1249): dieTrampoline supporting for Arm64.
	MOVD	R9, 8(RSP)
	BL	·dieHandler(SB)
