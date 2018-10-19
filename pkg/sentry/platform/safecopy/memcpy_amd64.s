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

// handleMemcpyFault returns (the value stored in AX, the value stored in DI).
// Control is transferred to it when memcpy below receives SIGSEGV or SIGBUS,
// with the faulting address stored in AX and the signal number stored in DI.
//
// It must have the same frame configuration as memcpy so that it can undo any
// potential call frame set up by the assembler.
TEXT handleMemcpyFault(SB), NOSPLIT, $0-36
	MOVQ	AX, addr+24(FP)
	MOVL	DI, sig+32(FP)
	RET

// memcpy copies data from src to dst. If a SIGSEGV or SIGBUS signal is received
// during the copy, it returns the address that caused the fault and the number
// of the signal that was received. Otherwise, it returns an unspecified address
// and a signal number of 0.
//
// Data is copied in order, such that if a fault happens at address p, it is
// safe to assume that all data before p-maxRegisterSize has already been
// successfully copied.
//
// The code is derived from the forward copying part of runtime.memmove.
//
// func memcpy(dst, src unsafe.Pointer, n uintptr) (fault unsafe.Pointer, sig int32)
TEXT ·memcpy(SB), NOSPLIT, $0-36
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemcpyFault will store a different value in this address.
	MOVL	$0, sig+32(FP)

	MOVQ	to+0(FP), DI
	MOVQ	from+8(FP), SI
	MOVQ	n+16(FP), BX

	// REP instructions have a high startup cost, so we handle small sizes
	// with some straightline code. The REP MOVSQ instruction is really fast
	// for large sizes. The cutover is approximately 2K.
tail:
	// move_129through256 or smaller work whether or not the source and the
	// destination memory regions overlap because they load all data into
	// registers before writing it back.  move_256through2048 on the other
	// hand can be used only when the memory regions don't overlap or the copy
	// direction is forward.
	TESTQ	BX, BX
	JEQ	move_0
	CMPQ	BX, $2
	JBE	move_1or2
	CMPQ	BX, $4
	JBE	move_3or4
	CMPQ	BX, $8
	JB	move_5through7
	JE	move_8
	CMPQ	BX, $16
	JBE	move_9through16
	CMPQ	BX, $32
	JBE	move_17through32
	CMPQ	BX, $64
	JBE	move_33through64
	CMPQ	BX, $128
	JBE	move_65through128
	CMPQ	BX, $256
	JBE	move_129through256
	// TODO: use branch table and BSR to make this just a single dispatch

/*
 * forward copy loop
 */
	CMPQ	BX, $2048
	JLS	move_256through2048

	// Check alignment
	MOVL	SI, AX
	ORL	DI, AX
	TESTL	$7, AX
	JEQ	fwdBy8

	// Do 1 byte at a time
	MOVQ	BX, CX
	REP;	MOVSB
	RET

fwdBy8:
	// Do 8 bytes at a time
	MOVQ	BX, CX
	SHRQ	$3, CX
	ANDQ	$7, BX
	REP;	MOVSQ
	JMP	tail

move_1or2:
	MOVB	(SI), AX
	MOVB	AX, (DI)
	MOVB	-1(SI)(BX*1), CX
	MOVB	CX, -1(DI)(BX*1)
	RET
move_0:
	RET
move_3or4:
	MOVW	(SI), AX
	MOVW	AX, (DI)
	MOVW	-2(SI)(BX*1), CX
	MOVW	CX, -2(DI)(BX*1)
	RET
move_5through7:
	MOVL	(SI), AX
	MOVL	AX, (DI)
	MOVL	-4(SI)(BX*1), CX
	MOVL	CX, -4(DI)(BX*1)
	RET
move_8:
	// We need a separate case for 8 to make sure we write pointers atomically.
	MOVQ	(SI), AX
	MOVQ	AX, (DI)
	RET
move_9through16:
	MOVQ	(SI), AX
	MOVQ	AX, (DI)
	MOVQ	-8(SI)(BX*1), CX
	MOVQ	CX, -8(DI)(BX*1)
	RET
move_17through32:
	MOVOU	(SI), X0
	MOVOU	X0, (DI)
	MOVOU	-16(SI)(BX*1), X1
	MOVOU	X1, -16(DI)(BX*1)
	RET
move_33through64:
	MOVOU	(SI), X0
	MOVOU	X0, (DI)
	MOVOU	16(SI), X1
	MOVOU	X1, 16(DI)
	MOVOU	-32(SI)(BX*1), X2
	MOVOU	X2, -32(DI)(BX*1)
	MOVOU	-16(SI)(BX*1), X3
	MOVOU	X3, -16(DI)(BX*1)
	RET
move_65through128:
	MOVOU	(SI), X0
	MOVOU	X0, (DI)
	MOVOU	16(SI), X1
	MOVOU	X1, 16(DI)
	MOVOU	32(SI), X2
	MOVOU	X2, 32(DI)
	MOVOU	48(SI), X3
	MOVOU	X3, 48(DI)
	MOVOU	-64(SI)(BX*1), X4
	MOVOU	X4, -64(DI)(BX*1)
	MOVOU	-48(SI)(BX*1), X5
	MOVOU	X5, -48(DI)(BX*1)
	MOVOU	-32(SI)(BX*1), X6
	MOVOU	X6, -32(DI)(BX*1)
	MOVOU	-16(SI)(BX*1), X7
	MOVOU	X7, -16(DI)(BX*1)
	RET
move_129through256:
	MOVOU	(SI), X0
	MOVOU	X0, (DI)
	MOVOU	16(SI), X1
	MOVOU	X1, 16(DI)
	MOVOU	32(SI), X2
	MOVOU	X2, 32(DI)
	MOVOU	48(SI), X3
	MOVOU	X3, 48(DI)
	MOVOU	64(SI), X4
	MOVOU	X4, 64(DI)
	MOVOU	80(SI), X5
	MOVOU	X5, 80(DI)
	MOVOU	96(SI), X6
	MOVOU	X6, 96(DI)
	MOVOU	112(SI), X7
	MOVOU	X7, 112(DI)
	MOVOU	-128(SI)(BX*1), X8
	MOVOU	X8, -128(DI)(BX*1)
	MOVOU	-112(SI)(BX*1), X9
	MOVOU	X9, -112(DI)(BX*1)
	MOVOU	-96(SI)(BX*1), X10
	MOVOU	X10, -96(DI)(BX*1)
	MOVOU	-80(SI)(BX*1), X11
	MOVOU	X11, -80(DI)(BX*1)
	MOVOU	-64(SI)(BX*1), X12
	MOVOU	X12, -64(DI)(BX*1)
	MOVOU	-48(SI)(BX*1), X13
	MOVOU	X13, -48(DI)(BX*1)
	MOVOU	-32(SI)(BX*1), X14
	MOVOU	X14, -32(DI)(BX*1)
	MOVOU	-16(SI)(BX*1), X15
	MOVOU	X15, -16(DI)(BX*1)
	RET
move_256through2048:
	SUBQ	$256, BX
	MOVOU	(SI), X0
	MOVOU	X0, (DI)
	MOVOU	16(SI), X1
	MOVOU	X1, 16(DI)
	MOVOU	32(SI), X2
	MOVOU	X2, 32(DI)
	MOVOU	48(SI), X3
	MOVOU	X3, 48(DI)
	MOVOU	64(SI), X4
	MOVOU	X4, 64(DI)
	MOVOU	80(SI), X5
	MOVOU	X5, 80(DI)
	MOVOU	96(SI), X6
	MOVOU	X6, 96(DI)
	MOVOU	112(SI), X7
	MOVOU	X7, 112(DI)
	MOVOU	128(SI), X8
	MOVOU	X8, 128(DI)
	MOVOU	144(SI), X9
	MOVOU	X9, 144(DI)
	MOVOU	160(SI), X10
	MOVOU	X10, 160(DI)
	MOVOU	176(SI), X11
	MOVOU	X11, 176(DI)
	MOVOU	192(SI), X12
	MOVOU	X12, 192(DI)
	MOVOU	208(SI), X13
	MOVOU	X13, 208(DI)
	MOVOU	224(SI), X14
	MOVOU	X14, 224(DI)
	MOVOU	240(SI), X15
	MOVOU	X15, 240(DI)
	CMPQ	BX, $256
	LEAQ	256(SI), SI
	LEAQ	256(DI), DI
	JGE	move_256through2048
	JMP	tail
