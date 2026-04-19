// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// handleMemcpyFault returns (the value stored in R0, the value stored in R1).
// Control is transferred to it when memcpy below receives SIGSEGV or SIGBUS,
// with the faulting address stored in R0 and the signal number stored in R1.
//
// It must have the same frame configuration as memcpy so that it can undo any
// potential call frame set up by the assembler.
TEXT handleMemcpyFault(SB), NOSPLIT, $0-36
	MOV A0, addr+24(FP)
	MOVW A1, sig+32(FP)
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
// The code is derived from the Go source runtime.memmove.
//
// func memcpy(dst, src unsafe.Pointer, n uintptr) (fault unsafe.Pointer, sig int32)
TEXT ·memcpy(SB), NOSPLIT, $-8-36
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemcpyFault will store a different value in this address.
	MOVW ZERO, sig+32(FP)

	MOV  dst+0(FP), T0
	MOV  src+8(FP), T1
	MOV  n+16(FP), T2
	ADD  T1, T2, T5

	// If the destination is ahead of the source, start at the end of the
	// buffer and go backward.
	//BLTU	T1, T0, b

	// If less than eight bytes, do one byte at a time.
	SLTU	$8, T2, T3
	BNE	T3, ZERO, f_outcheck

	// Do one byte at a time until from is eight-aligned.
	JMP	f_aligncheck
f_align:
	MOVB	(T1), T3
	MOVB	T3, (T0)
	ADD	$1, T0
	ADD	$1, T1
f_aligncheck:
	AND	$7, T1, T3
	BNE	T3, ZERO, f_align

	// Do eight bytes at a time as long as there is room.
	ADD	$-7, T5, T6
	JMP	f_wordscheck
f_words:
	MOV	(T1), T3
	MOV	T3, (T0)
	ADD	$8, T0
	ADD	$8, T1
f_wordscheck:
	SLTU	T6, T1, T3
	BNE	T3, ZERO, f_words

	// Finish off the remaining partial word.
	JMP 	f_outcheck
f_out:
	MOVB	(T1), T3
	MOVB	T3, (T0)
	ADD	$1, T0
	ADD	$1, T1
f_outcheck:
	BNE	T1, T5, f_out

	RET

b:
	ADD	T0, T2, T4
	// If less than eight bytes, do one byte at a time.
	SLTU	$8, T2, T3
	BNE	T3, ZERO, b_outcheck

	// Do one byte at a time until from+n is eight-aligned.
	JMP	b_aligncheck
b_align:
	ADD	$-1, T4
	ADD	$-1, T5
	MOVB	(T5), T3
	MOVB	T3, (T4)
b_aligncheck:
	AND	$7, T5, T3
	BNE	T3, ZERO, b_align

	// Do eight bytes at a time as long as there is room.
	ADD	$7, T1, T6
	JMP	b_wordscheck
b_words:
	ADD	$-8, T4
	ADD	$-8, T5
	MOV	(T5), T3
	MOV	T3, (T4)
b_wordscheck:
	SLTU	T5, T6, T3
	BNE	T3, ZERO, b_words

	// Finish off the remaining partial word.
	JMP	b_outcheck
b_out:
	ADD	$-1, T4
	ADD	$-1, T5
	MOVB	(T5), T3
	MOVB	T3, (T4)
b_outcheck:
	BNE	T5, T1, b_out

	RET

// func addrOfMemcpy() uintptr
TEXT ·addrOfMemcpy(SB), $0-8
	MOV	$·memcpy(SB), A0
	MOV	A0, ret+0(FP)
	RET
