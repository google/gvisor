// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// handleMemclrFault returns (the value stored in AX, the value stored in DI).
// Control is transferred to it when memclr below receives SIGSEGV or SIGBUS,
// with the faulting address stored in AX and the signal number stored in DI.
//
// It must have the same frame configuration as memclr so that it can undo any
// potential call frame set up by the assembler.
TEXT handleMemclrFault(SB), NOSPLIT, $0-28
	MOVQ	AX, addr+16(FP)
	MOVL	DI, sig+24(FP)
	RET

// memclr sets the n bytes following ptr to zeroes. If a SIGSEGV or SIGBUS
// signal is received during the write, it returns the address that caused the
// fault and the number of the signal that was received. Otherwise, it returns
// an unspecified address and a signal number of 0.
//
// Data is written in order, such that if a fault happens at address p, it is
// safe to assume that all data before p-maxRegisterSize has already been
// successfully written.
//
// The code is derived from runtime.memclrNoHeapPointers.
//
// func memclr(ptr unsafe.Pointer, n uintptr) (fault unsafe.Pointer, sig int32)
TEXT ·memclr(SB), NOSPLIT, $0-28
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemclrFault will store a different value in this address.
	MOVL	$0, sig+24(FP)

	MOVQ	ptr+0(FP), DI
	MOVQ	n+8(FP), BX
	XORQ	AX, AX

	// MOVOU seems always faster than REP STOSQ.
tail:
	TESTQ	BX, BX
	JEQ	_0
	CMPQ	BX, $2
	JBE	_1or2
	CMPQ	BX, $4
	JBE	_3or4
	CMPQ	BX, $8
	JB	_5through7
	JE	_8
	CMPQ	BX, $16
	JBE	_9through16
	PXOR	X0, X0
	CMPQ	BX, $32
	JBE	_17through32
	CMPQ	BX, $64
	JBE	_33through64
	CMPQ	BX, $128
	JBE	_65through128
	CMPQ	BX, $256
	JBE	_129through256
	// TODO: use branch table and BSR to make this just a single dispatch
	// TODO: for really big clears, use MOVNTDQ, even without AVX2.

loop:
	MOVOU	X0, 0(DI)
	MOVOU	X0, 16(DI)
	MOVOU	X0, 32(DI)
	MOVOU	X0, 48(DI)
	MOVOU	X0, 64(DI)
	MOVOU	X0, 80(DI)
	MOVOU	X0, 96(DI)
	MOVOU	X0, 112(DI)
	MOVOU	X0, 128(DI)
	MOVOU	X0, 144(DI)
	MOVOU	X0, 160(DI)
	MOVOU	X0, 176(DI)
	MOVOU	X0, 192(DI)
	MOVOU	X0, 208(DI)
	MOVOU	X0, 224(DI)
	MOVOU	X0, 240(DI)
	SUBQ	$256, BX
	ADDQ	$256, DI
	CMPQ	BX, $256
	JAE	loop
	JMP	tail

_1or2:
	MOVB	AX, (DI)
	MOVB	AX, -1(DI)(BX*1)
	RET
_0:
	RET
_3or4:
	MOVW	AX, (DI)
	MOVW	AX, -2(DI)(BX*1)
	RET
_5through7:
	MOVL	AX, (DI)
	MOVL	AX, -4(DI)(BX*1)
	RET
_8:
	// We need a separate case for 8 to make sure we clear pointers atomically.
	MOVQ	AX, (DI)
	RET
_9through16:
	MOVQ	AX, (DI)
	MOVQ	AX, -8(DI)(BX*1)
	RET
_17through32:
	MOVOU	X0, (DI)
	MOVOU	X0, -16(DI)(BX*1)
	RET
_33through64:
	MOVOU	X0, (DI)
	MOVOU	X0, 16(DI)
	MOVOU	X0, -32(DI)(BX*1)
	MOVOU	X0, -16(DI)(BX*1)
	RET
_65through128:
	MOVOU	X0, (DI)
	MOVOU	X0, 16(DI)
	MOVOU	X0, 32(DI)
	MOVOU	X0, 48(DI)
	MOVOU	X0, -64(DI)(BX*1)
	MOVOU	X0, -48(DI)(BX*1)
	MOVOU	X0, -32(DI)(BX*1)
	MOVOU	X0, -16(DI)(BX*1)
	RET
_129through256:
	MOVOU	X0, (DI)
	MOVOU	X0, 16(DI)
	MOVOU	X0, 32(DI)
	MOVOU	X0, 48(DI)
	MOVOU	X0, 64(DI)
	MOVOU	X0, 80(DI)
	MOVOU	X0, 96(DI)
	MOVOU	X0, 112(DI)
	MOVOU	X0, -128(DI)(BX*1)
	MOVOU	X0, -112(DI)(BX*1)
	MOVOU	X0, -96(DI)(BX*1)
	MOVOU	X0, -80(DI)(BX*1)
	MOVOU	X0, -64(DI)(BX*1)
	MOVOU	X0, -48(DI)(BX*1)
	MOVOU	X0, -32(DI)(BX*1)
	MOVOU	X0, -16(DI)(BX*1)
	RET
