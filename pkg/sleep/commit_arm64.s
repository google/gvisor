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

#define preparingG 1

// See commit_noasm.go for a description of commitSleep.
//
// func commitSleep(g uintptr, waitingG *uintptr) bool
TEXT ·commitSleep(SB),NOSPLIT,$0-24
	MOVD waitingG+8(FP), R0
	MOVD $preparingG, R1
	MOVD G+0(FP), R2

	// Store the G in waitingG if it's still preparingG. If it's anything
	// else it means a waker has aborted the sleep.
again:
        LDAXR   (R0), R3
        CMP     R1, R3
        BNE     ok
        STLXR   R2, (R0), R3
        CBNZ    R3, again
ok:
        CSET    EQ, R0
        MOVB    R0, ret+16(FP)
        RET
