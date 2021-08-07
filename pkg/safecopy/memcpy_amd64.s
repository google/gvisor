// Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
// Revisions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com).  All rights reserved.
// Portions Copyright 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

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
// func Memcpy(dst, src unsafe.Pointer, n uintptr) (fault unsafe.Pointer, sig int32)
TEXT ·Memcpy(SB), NOSPLIT, $0-36
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemcpyFault will store a different value in this address.
	MOVL	$0, sig+32(FP)

	MOVQ	dst+0(FP), DI
	MOVQ	src+8(FP), SI
	MOVQ	n+16(FP), BX

tail:
	// BSR+branch table make almost all memmove/memclr benchmarks worse. Not
	// worth doing.
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

move_257plus:
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
	JGE	move_257plus
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

// func addrOfMemcpy() uintptr
TEXT ·addrOfMemcpy(SB), $0-8
	MOVQ	$·Memcpy(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
