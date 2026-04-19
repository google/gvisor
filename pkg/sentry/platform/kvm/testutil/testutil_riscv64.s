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

// +build riscv64

// test_util_riscv64.s provides RISCV64 test functions.

#include "funcdata.h"
#include "textflag.h"

#define SYS_GETPID 172

// This function simulates the getpid syscall.
TEXT ·Getpid(SB),NOSPLIT,$0
	NO_LOCAL_POINTERS
	MOV $SYS_GETPID, A7
	ECALL
	RET

TEXT ·AddrOfGetpid(SB),NOSPLIT,$0-8
	MOV $·Getpid(SB), A0
	MOV A0, ret+0(FP)
	RET

TEXT ·touch(SB),NOSPLIT,$0
start:
	MOV 0(A6), A1
	MOV $SYS_GETPID, A7   // getpid
	ECALL
	JMP start

TEXT ·AddrOfTouch(SB),NOSPLIT,$0-8
	MOV $·touch(SB), A0
	MOV A0, ret+0(FP)
	RET

TEXT ·haltLoop(SB),NOSPLIT,$0
start:
	//WORD $0x10500073 // WFI
	JMP start

TEXT ·AddrOfHaltLoop(SB),NOSPLIT,$0-8
	MOV $·haltLoop(SB), A0
	MOV A0, ret+0(FP)
	RET

// This function simulates a loop of syscall.
TEXT ·syscallLoop(SB),NOSPLIT,$0
start:
	ECALL
	JMP start

TEXT ·AddrOfSyscallLoop(SB),NOSPLIT,$0-8
	MOV $·syscallLoop(SB), A0
	MOV A0, ret+0(FP)
	RET

TEXT ·spinLoop(SB),NOSPLIT,$0
start:
	JMP start

TEXT ·AddrOfSpinLoop(SB),NOSPLIT,$0-8
	MOV $·spinLoop(SB), A0
	MOV A0, ret+0(FP)
	RET

TEXT ·TLSWorks(SB),NOSPLIT,$0
        NO_LOCAL_POINTERS
        MOV $0x6789, A5
        MOV A5, TP
        MOV $SYS_GETPID, A7 // getpid
        ECALL
	// trigger SIGILL to enter bluepill()
	WORD $0x14002573 // csrr a0, sscratch
        MOV TP, A6
	BNE A5, A6, isNaN
        MOV $1, A0
        MOV A0, ret+0(FP)
        RET
isNaN:
        MOV ZERO, ret+0(FP)
        RET

TEXT ·FloatingPointWorks(SB),NOSPLIT,$0
	NO_LOCAL_POINTERS
	// gc will touch fpsimd, so we should test it.
	// such as in <runtime.deductSweepCredit>.
	MOV $0xa, T0
	FCVTSL T0, F0
	MOV $SYS_GETPID, A7 // getpid
	ECALL
	FCVTSL T0, F1
	FEQS F0, F1, A0
	MOV A0, ret+0(FP)
	RET

// NOT: bitwise logical NOT
// This case simulates an application that modified X1-X31.
#define TWIDDLE_REGS() \
        NOT X1; \
        NOT X2; \
        NOT X3; \
	NOT TP; \
        NOT X5; \
        NOT X6; \
        NOT X7; \
        NOT X8; \
        NOT X9; \
        NOT X10; \
        NOT X11; \
        NOT X12; \
        NOT X13; \
        NOT X14; \
        NOT X15; \
        NOT X16; \
        NOT X17; \
        NOT X18; \
        NOT X19; \
        NOT X20; \
        NOT X21; \
        NOT X22; \
        NOT X23; \
        NOT X24; \
        NOT X25; \
        NOT X26; \
	NOT g; \
        NOT X28; \
        NOT X29; \
        NOT X30; \
	NOT X31; 

TEXT ·twiddleRegsSyscall(SB),NOSPLIT,$0
	TWIDDLE_REGS()
	ECALL
	RET // never reached

TEXT ·AddrOfTwiddleRegsSyscall(SB),NOSPLIT,$0-8
	MOV $·twiddleRegsSyscall(SB), A0
	MOV A0, ret+0(FP)
	RET

TEXT ·twiddleRegsFault(SB),NOSPLIT,$0
	TWIDDLE_REGS()
	// Trapped in el0_ia.
	// Branch to Register branches unconditionally to an address in <Rn>.
	JMP (A6) // <=> br x6, must fault
	RET // never reached

TEXT ·AddrOfTwiddleRegsFault(SB),NOSPLIT,$0-8
	MOV $·twiddleRegsFault(SB), A0
	MOV A0, ret+0(FP)
	RET
