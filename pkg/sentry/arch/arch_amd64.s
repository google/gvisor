// Copyright 2018 Google LLC
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

// MXCSR_DEFAULT is the reset value of MXCSR (Intel SDM Vol. 2, Ch. 3.2
// "LDMXCSR")
#define MXCSR_DEFAULT	0x1f80

// MXCSR_OFFSET is the offset in bytes of the MXCSR field from the start of the
// FXSAVE/XSAVE area. (Intel SDM Vol. 1, Table 10-2 "Format of an FXSAVE Area")
#define MXCSR_OFFSET	24

// initX86FPState initializes floating point state.
//
// func initX86FPState(data *FloatingPointData, useXsave bool)
//
// We need to clear out and initialize an empty fp state area since the sentry
// may have left sensitive information in the floating point registers.
//
// Preconditions: data is zeroed
TEXT ·initX86FPState(SB), $24-16
	// Save MXCSR (callee-save)
	STMXCSR	mxcsr-8(SP)

	// Save x87 CW (callee-save)
	FSTCW	cw-16(SP)

	MOVQ	fpState+0(FP), DI

	// Do we use xsave?
	MOVBQZX	useXsave+8(FP), AX
	TESTQ	AX, AX
	JZ	no_xsave

	// Use XRSTOR to clear all FP state to an initial state.
	//
	// The fpState XSAVE area is zeroed on function entry, meaning
	// XSTATE_BV is zero.
	//
	// "If RFBM[i] = 1 and bit i is clear in the XSTATE_BV field in the
	// XSAVE header, XRSTOR initializes state component i."
	//
	// Initialization is defined in SDM Vol 1, Chapter 13.3. It puts all
	// the registers in a reasonable initial state, except MXCSR:
	//
	// "The MXCSR register is part of state component 1, SSE state (see
	// Section 13.5.2). However, the standard form of XRSTOR loads the
	// MXCSR register from memory whenever the RFBM[1] (SSE) or RFBM[2]
	// (AVX) is set, regardless of the values of XSTATE_BV[1] and
	// XSTATE_BV[2]."

	// Set MXCSR to the default value.
	MOVL	$MXCSR_DEFAULT, MXCSR_OFFSET(DI)

	// Initialize registers with XRSTOR.
	MOVL	$0xffffffff, AX
	MOVL	$0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x2f // XRSTOR64 0(DI)

	// Now that all the state has been reset, write it back out to the
	// XSAVE area.
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x27 // XSAVE64 0(DI)

	JMP	out

no_xsave:
	// Clear out existing X values.
	PXOR	X0, X0
	MOVO	X0, X1
	MOVO	X0, X2
	MOVO	X0, X3
	MOVO	X0, X4
	MOVO	X0, X5
	MOVO	X0, X6
	MOVO	X0, X7
	MOVO	X0, X8
	MOVO	X0, X9
	MOVO	X0, X10
	MOVO	X0, X11
	MOVO	X0, X12
	MOVO	X0, X13
	MOVO	X0, X14
	MOVO	X0, X15

	// Zero out %rax and store into MMX registers. MMX registers are
	// an alias of 8x64 bits of the 8x80 bits used for the original
	// x87 registers. Storing zero into them will reset the FPU registers
	// to bits [63:0] = 0, [79:64] = 1. But the contents aren't too
	// important, just the fact that we have reset them to a known value.
	XORQ	AX, AX
	MOVQ	AX, M0
	MOVQ	AX, M1
	MOVQ	AX, M2
	MOVQ	AX, M3
	MOVQ	AX, M4
	MOVQ	AX, M5
	MOVQ	AX, M6
	MOVQ	AX, M7

	// The Go assembler doesn't support FNINIT, so we use BYTE.
	// This will:
	//  - Reset FPU control word to 0x037f
	//  - Clear FPU status word
	//  - Reset FPU tag word to 0xffff
	//  - Clear FPU data pointer
	//  - Clear FPU instruction pointer
	BYTE $0xDB; BYTE $0xE3; // FNINIT

	// Reset MXCSR.
	MOVL	$MXCSR_DEFAULT, tmpmxcsr-24(SP)
	LDMXCSR	tmpmxcsr-24(SP)

	// Save the floating point state with fxsave.
	FXSAVE64	0(DI)

out:
	// Restore MXCSR.
	LDMXCSR	mxcsr-8(SP)

	// Restore x87 CW.
	FLDCW	cw-16(SP)

	RET
