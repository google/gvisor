// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

#include "funcdata.h"
#include "textflag.h"

// func muldiv64(value, multiplier, divisor uint64) (uint64, bool)
//
// Computes (value * multiplier) / divisor with overflow detection.
//
// The 128-bit product is built with MULV (low 64 = MUL.D) and MULHVU
// (high 64 = MULH.D.U). If the high word is >= divisor, the quotient
// would overflow uint64, so we report failure. Otherwise we delegate the
// 128/64 division to the Go helper divWW from arith_loong64.go.
TEXT ·muldiv64(SB),NOSPLIT,$40-33
	NO_LOCAL_POINTERS
	MOVV	value+0(FP), R4
	MOVV	multiplier+8(FP), R5
	MOVV	divisor+16(FP), R6

	MULV	R5, R4, R7     // R7 = low 64 bits of R4 * R5
	MULHVU	R5, R4, R8     // R8 = high 64 bits, unsigned

	BGEU	R8, R6, overflow

	// Pass arguments to divWW on the stack (Plan 9 ABI): u1, u0, v.
	MOVV	R8, 8(R3)
	MOVV	R7, 16(R3)
	MOVV	R6, 24(R3)
	CALL	·divWW(SB)
	MOVV	32(R3), R4     // q = first return of divWW
	MOVV	R4, ret+24(FP)
	MOVV	$1, R4
	MOVB	R4, ret1+32(FP)
	RET

overflow:
	MOVV	R0, ret+24(FP)
	MOVB	R0, ret1+32(FP)
	RET
