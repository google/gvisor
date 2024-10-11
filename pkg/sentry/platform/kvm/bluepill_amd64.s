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

// ENTRY_CPU_SELF is the location of the CPU in the entry struct.
//
// This is sourced from ring0.
#define ENTRY_CPU_SELF 272 // +checkoffset ring0 kernelEntry.cpuSelf

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

// System call definitions.
#define SYS_MMAP 9

TEXT ·sigsysHandler(SB),NOSPLIT|NOFRAME,$0
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

TEXT ·getcs(SB), $0-2
	MOVW CS, AX
	MOVW AX, ret+0(FP)
	RET

TEXT ·addrOfBluepillUserHandler(SB), $0-8
	MOVQ $·bluepillUserHandler(SB), AX
	MOVQ AX, ret+0(FP)
	RET

// func addrOfSighandler() uintptr
TEXT ·addrOfSigsysHandler(SB), $0-8
	MOVQ $·sigsysHandler(SB), AX
	MOVQ AX, ret+0(FP)
	RET

// dieTrampoline: see bluepill.go, bluepill_amd64_unsafe.go for documentation.
TEXT ·dieTrampoline(SB),NOSPLIT|NOFRAME,$0
	PUSHQ BX // First argument (vCPU).
	PUSHQ AX // Fake the old RIP as caller.
	JMP ·dieHandler(SB)

// func addrOfDieTrampoline() uintptr
TEXT ·addrOfDieTrampoline(SB), $0-8
	MOVQ $·dieTrampoline(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·currentCPU(SB), $0-8
	MOVQ ENTRY_CPU_SELF(GS), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·rdfsbase(SB), $0-8
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0xc0;
	MOVQ AX, ret+0(FP)
	RET

TEXT ·rdgsbase(SB), $0-8
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0xc8;
	MOVQ AX, ret+0(FP)
	RET
