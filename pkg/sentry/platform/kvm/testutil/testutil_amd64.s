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

// +build amd64

// test_util_amd64.s provides AMD64 test functions.

#include "funcdata.h"
#include "textflag.h"

TEXT ·Getpid(SB),NOSPLIT,$0
	NO_LOCAL_POINTERS
	MOVQ $39, AX // getpid
	SYSCALL
	RET

// func AddrOfGetpid() uintptr
TEXT ·AddrOfGetpid(SB), $0-8
	MOVQ $·Getpid(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·touch(SB),NOSPLIT,$0
start:
	MOVQ 0(AX), BX // deref AX
	MOVQ $39, AX   // getpid
	SYSCALL
	JMP start

// func AddrOfTouch() uintptr
TEXT ·AddrOfTouch(SB), $0-8
	MOVQ $·touch(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·syscallLoop(SB),NOSPLIT,$0
start:
	SYSCALL
	JMP start

// func AddrOfSyscallLoop() uintptr
TEXT ·AddrOfSyscallLoop(SB), $0-8
	MOVQ $·syscallLoop(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·spinLoop(SB),NOSPLIT,$0
start:
	JMP start

// func AddrOfSpinLoop() uintptr
TEXT ·AddrOfSpinLoop(SB), $0-8
	MOVQ $·spinLoop(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·FloatingPointWorks(SB),NOSPLIT,$0-8
	NO_LOCAL_POINTERS
	MOVQ $1, AX
	MOVQ AX, X0
	MOVQ $39, AX // getpid
	SYSCALL
	MOVQ X0, AX
	CMPQ AX, $1
	SETEQ ret+0(FP)
	RET

#define TWIDDLE_REGS() \
	NOTQ R15; \
	NOTQ R14; \
	NOTQ R13; \
	NOTQ R12; \
	NOTQ BP; \
	NOTQ BX; \
	NOTQ R11; \
	NOTQ R10; \
	NOTQ R9; \
	NOTQ R8; \
	NOTQ AX; \
	NOTQ CX; \
	NOTQ DX; \
	NOTQ SI; \
	NOTQ DI; \
	NOTQ SP;

TEXT ·twiddleRegsSyscall(SB),NOSPLIT,$0
	TWIDDLE_REGS()
	SYSCALL
	RET // never reached

// func AddrOfTwiddleRegsSyscall() uintptr
TEXT ·AddrOfTwiddleRegsSyscall(SB), $0-8
	MOVQ $·twiddleRegsSyscall(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·twiddleRegsFault(SB),NOSPLIT,$0
	TWIDDLE_REGS()
	JMP AX // must fault
	RET // never reached

// func AddrOfTwiddleRegsFault() uintptr
TEXT ·AddrOfTwiddleRegsFault(SB), $0-8
	MOVQ $·twiddleRegsFault(SB), AX
	MOVQ AX, ret+0(FP)
	RET

#define READ_FS() BYTE $0x64; BYTE $0x48; BYTE $0x8b; BYTE $0x00;
#define READ_GS() BYTE $0x65; BYTE $0x48; BYTE $0x8b; BYTE $0x00;

TEXT ·twiddleSegments(SB),NOSPLIT,$0
	MOVQ $0x0, AX
	READ_GS()
	MOVQ AX, BX
	MOVQ $0x0, AX
	READ_FS()
	SYSCALL
	RET // never reached

// func AddrOfTwiddleSegments() uintptr
TEXT ·AddrOfTwiddleSegments(SB), $0-8
	MOVQ $·twiddleSegments(SB), AX
	MOVQ AX, ret+0(FP)
	RET
