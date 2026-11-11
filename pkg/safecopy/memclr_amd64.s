// Copyright 2014 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

#include "textflag.h"

// handleMemclrFault returns (the value stored in AX, the value stored in DI),
// or restarts memclr. Control is transferred to it when memclr below receives
// SIGSEGV or SIGBUS, with the faulting address stored in AX and the signal
// number stored in DI.
//
// It must have the same frame configuration as memclr so that it can undo any
// potential call frame set up by the assembler.
TEXT handleMemclrFault(SB), NOSPLIT|NOFRAME, $0-36
	// Order non-temporal stores before the fault like a successful memclr.
	SFENCE
	// If REP STOSB faulted, it wrote everything before R8-CX, where R8 is
	// the end of its range and CX is its remaining count. Restart from there
	// with fast set to false.
	TESTQ	R8, R8
	JNE	restart
	MOVQ	AX, addr+24(FP)
	MOVL	DI, sig+32(FP)
	RET
restart:
	SUBQ	CX, R8
	MOVQ	R8, ptr+0(FP)
	MOVQ	CX, n+8(FP)
	MOVB	$0, fast+16(FP)
	JMP	·memclr(SB)

// See the corresponding doc in safecopy_unsafe.go.
//
// The code is derived from runtime.memclrNoHeapPointers.
//
// func memclr(ptr unsafe.Pointer, n uintptr, fast bool) (fault unsafe.Pointer, sig int32)
TEXT ·memclr(SB), NOSPLIT|NOFRAME, $0-36
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemclrFault will store a different value in this address.
	MOVL	$0, sig+32(FP)

	MOVQ	ptr+0(FP), DI
	MOVQ	n+8(FP), BX
	XORQ	AX, AX
	XORQ	R8, R8

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
	CMPQ	BX, $0x2000000
	JAE	loop_preheader_nt
	// Like the runtime's memclr, use REP STOS from 2 KB if it is fast.
	CMPB	fast+16(FP), $0
	JEQ	loop
	CMPB	·hasERMS(SB), $0
	JEQ	loop
	CMPQ	BX, $2048
	JAE	rep_stosb
	// TODO: use branch table and BSR to make this just a single dispatch

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

rep_stosb:
	MOVQ	BX, CX
	LEAQ	(DI)(BX*1), R8
	REP;	STOSB
	RET

	// Non-temporal stores neither read nor cache the destination, which
	// makes them faster for large ranges. Like the runtime's memclr, use
	// them for 32 MB and above.
loop_preheader_nt:
	// MOVNTDQ requires 16-byte alignment.
	MOVOU	X0, 0(DI)
	MOVQ	DI, SI
	ADDQ	$16, DI
	ANDQ	$~15, DI
	SUBQ	DI, SI
	ADDQ	SI, BX
loop_nt:
	MOVNTO	X0, 0(DI)
	MOVNTO	X0, 16(DI)
	MOVNTO	X0, 32(DI)
	MOVNTO	X0, 48(DI)
	MOVNTO	X0, 64(DI)
	MOVNTO	X0, 80(DI)
	MOVNTO	X0, 96(DI)
	MOVNTO	X0, 112(DI)
	MOVNTO	X0, 128(DI)
	MOVNTO	X0, 144(DI)
	MOVNTO	X0, 160(DI)
	MOVNTO	X0, 176(DI)
	MOVNTO	X0, 192(DI)
	MOVNTO	X0, 208(DI)
	MOVNTO	X0, 224(DI)
	MOVNTO	X0, 240(DI)
	SUBQ	$256, BX
	ADDQ	$256, DI
	CMPQ	BX, $256
	JAE	loop_nt
	SFENCE
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

// func addrOfMemclr() uintptr
TEXT ·addrOfMemclr(SB), $0-8
	MOVQ	$·memclr(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
