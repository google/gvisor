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

#include "textflag.h"

// VCPU_CPU is the location of the CPU in the vCPU struct.
//
// This is guaranteed to be zero.
#define VCPU_CPU 0x0

// Context offsets.
//
// Only limited use of the context is done in the assembly stub below, most is
// done in the Go handlers. However, the RIP must be examined.
#define CONTEXT_RAX 0x90
#define CONTEXT_RIP 0xa8
#define CONTEXT_FP  0xe0

// CLI is the literal byte for the disable interrupts instruction.
//
// This is checked as the source of the fault.
#define CLI $0xfa

#define SYS_MMAP 9

// See bluepill.go.
TEXT ·bluepill(SB),NOSPLIT,$0
begin:
	MOVQ vcpu+0(FP), AX
	LEAQ VCPU_CPU(AX), BX

	// The gorountine stack will be changed in guest which renders
	// the frame pointer outdated and misleads perf tools.
	// Disconnect the frame-chain with the zeroed frame pointer
	// when it is saved in the frame in bluepillHandler().
	MOVQ BP, CX
	MOVQ $0, BP
	BYTE CLI;
	MOVQ CX, BP
check_vcpu:
	MOVQ ENTRY_CPU_SELF(GS), CX
	CMPQ BX, CX
	JE right_vCPU
wrong_vcpu:
	CALL ·redpill(SB)
	JMP begin
right_vCPU:
	RET

// sighandler: see bluepill.go for documentation.
//
// The arguments are the following:
//
// 	DI - The signal number.
// 	SI - Pointer to siginfo_t structure.
// 	DX - Pointer to ucontext structure.
//
TEXT ·sighandler(SB),NOSPLIT,$0
	// Check if the signal is from the kernel.
	MOVQ $0x80, CX
	CMPL CX, 0x8(SI)
	JNE fallback

	// Check if RIP is disable interrupts.
	MOVQ CONTEXT_RIP(DX), CX
	CMPQ CX, $0x0
	JE fallback
	CMPB 0(CX), CLI
	JNE fallback

	// Call the bluepillHandler.
	PUSHQ DX                    // First argument (context).
	CALL ·bluepillHandler(SB)   // Call the handler.
	POPQ DX                     // Discard the argument.
	RET

fallback:
	// Jump to the previous signal handler.
	XORQ CX, CX
	MOVQ ·savedHandler(SB), AX
	JMP AX

// func addrOfSighandler() uintptr
TEXT ·addrOfSighandler(SB), $0-8
	MOVQ $·sighandler(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·sigsysHandler(SB),NOSPLIT,$0
	// Check if the signal is from the kernel.
	MOVQ $1, CX
	CMPL CX, 0x8(SI)
	JNE fallback

	MOVL CONTEXT_RAX(DX), CX
	CMPL CX, $SYS_MMAP
	JNE fallback
	PUSHQ DX                    // First argument (context).
	CALL ·seccompMmapHandler(SB)    // Call the handler.
	POPQ DX                     // Discard the argument.
	RET
fallback:
	// Jump to the previous signal handler.
	XORQ CX, CX
	MOVQ ·savedSigsysHandler(SB), AX
	JMP AX

// func addrOfSighandler() uintptr
TEXT ·addrOfSigsysHandler(SB), $0-8
	MOVQ $·sigsysHandler(SB), AX
	MOVQ AX, ret+0(FP)
	RET

// dieTrampoline: see bluepill.go, bluepill_amd64_unsafe.go for documentation.
TEXT ·dieTrampoline(SB),NOSPLIT,$0
	PUSHQ BX // First argument (vCPU).
	PUSHQ AX // Fake the old RIP as caller.
	JMP ·dieHandler(SB)

// func addrOfDieTrampoline() uintptr
TEXT ·addrOfDieTrampoline(SB), $0-8
	MOVQ $·dieTrampoline(SB), AX
	MOVQ AX, ret+0(FP)
	RET
