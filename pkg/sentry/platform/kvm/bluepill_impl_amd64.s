// build +amd64

// Automatically generated, do not edit.

// CPU offsets.
#define CPU_REGISTERS        0x30
#define CPU_ERROR_CODE       0x10
#define CPU_ERROR_TYPE       0x18
#define CPU_ENTRY            0x20
#define CPU_HAS_XSAVE        0x28
#define CPU_HAS_XSAVEOPT     0x29
#define CPU_FPU_STATE        0x108

// CPU entry offsets.
#define ENTRY_SCRATCH0       0x100
#define ENTRY_STACK_TOP      0x108
#define ENTRY_CPU_SELF       0x110
#define ENTRY_KERNEL_CR3     0x118

// Bits.
#define _RFLAGS_IF           0x200
#define _RFLAGS_IOPL0         0x1000
#define _KERNEL_FLAGS        0x02

// Vectors.
#define DivideByZero               0x00
#define Debug                      0x01
#define NMI                        0x02
#define Breakpoint                 0x03
#define Overflow                   0x04
#define BoundRangeExceeded         0x05
#define InvalidOpcode              0x06
#define DeviceNotAvailable         0x07
#define DoubleFault                0x08
#define CoprocessorSegmentOverrun  0x09
#define InvalidTSS                 0x0a
#define SegmentNotPresent          0x0b
#define StackSegmentFault          0x0c
#define GeneralProtectionFault     0x0d
#define PageFault                  0x0e
#define X87FloatingPointException  0x10
#define AlignmentCheck             0x11
#define MachineCheck               0x12
#define SIMDFloatingPointException 0x13
#define VirtualizationException    0x14
#define SecurityException          0x1e
#define SyscallInt80               0x80
#define Syscall                    0x100

// Ptrace registers.
#define PTRACE_R15      0x00
#define PTRACE_R14      0x08
#define PTRACE_R13      0x10
#define PTRACE_R12      0x18
#define PTRACE_RBP      0x20
#define PTRACE_RBX      0x28
#define PTRACE_R11      0x30
#define PTRACE_R10      0x38
#define PTRACE_R9       0x40
#define PTRACE_R8       0x48
#define PTRACE_RAX      0x50
#define PTRACE_RCX      0x58
#define PTRACE_RDX      0x60
#define PTRACE_RSI      0x68
#define PTRACE_RDI      0x70
#define PTRACE_ORIGRAX  0x78
#define PTRACE_RIP      0x80
#define PTRACE_CS       0x88
#define PTRACE_FLAGS    0x90
#define PTRACE_RSP      0x98
#define PTRACE_SS       0xa0
#define PTRACE_FS_BASE  0xa8
#define PTRACE_GS_BASE  0xb0
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
