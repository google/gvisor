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

// +build arm64

// test_util_arm64.s provides ARM64 test functions.

#include "funcdata.h"
#include "textflag.h"

#define SYS_GETPID 172

// This function simulates the getpid syscall.
TEXT ·Getpid(SB),NOSPLIT,$0
	NO_LOCAL_POINTERS
	MOVD $SYS_GETPID, R8
	SVC
	RET

TEXT ·Touch(SB),NOSPLIT,$0
start:
	MOVD 0(R8), R1
	MOVD $SYS_GETPID, R8   // getpid
	SVC
	B start

TEXT ·HaltLoop(SB),NOSPLIT,$0
start:
	HLT
	B start

// This function simulates a loop of syscall.
TEXT ·SyscallLoop(SB),NOSPLIT,$0
start:
	SVC
	B start

TEXT ·SpinLoop(SB),NOSPLIT,$0
start:
	B start

TEXT ·FloatingPointWorks(SB),NOSPLIT,$0-8
	NO_LOCAL_POINTERS
	FMOVD $(9.9), F0
	MOVD $SYS_GETPID, R8 // getpid
	SVC
	FMOVD $(9.9), F1
	FCMPD F0, F1
	BNE isNaN
	MOVD $1, R0
	MOVD R0, ret+0(FP)
	RET
isNaN:
	MOVD $0, ret+0(FP)
	RET

// MVN: bitwise logical NOT
// This case simulates an application that modified R0-R30.
#define TWIDDLE_REGS() \
        MVN R0, R0; \
        MVN R1, R1; \
        MVN R2, R2; \
        MVN R3, R3; \
        MVN R4, R4; \
        MVN R5, R5; \
        MVN R6, R6; \
        MVN R7, R7; \
        MVN R8, R8; \
        MVN R9, R9; \
        MVN R10, R10; \
        MVN R11, R11; \
        MVN R12, R12; \
        MVN R13, R13; \
        MVN R14, R14; \
        MVN R15, R15; \
        MVN R16, R16; \
        MVN R17, R17; \
        MVN R18_PLATFORM, R18_PLATFORM; \
        MVN R19, R19; \
        MVN R20, R20; \
        MVN R21, R21; \
        MVN R22, R22; \
        MVN R23, R23; \
        MVN R24, R24; \
        MVN R25, R25; \
        MVN R26, R26; \
        MVN R27, R27; \
        MVN g, g; \
        MVN R29, R29; \
        MVN R30, R30;

TEXT ·TwiddleRegsSyscall(SB),NOSPLIT,$0
	TWIDDLE_REGS()
	SVC
	RET // never reached
