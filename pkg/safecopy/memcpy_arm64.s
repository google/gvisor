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
	MOVD R0, addr+24(FP)
	MOVW R1, sig+32(FP)
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
	MOVW $0, sig+32(FP)

	MOVD to+0(FP), R3
	MOVD from+8(FP), R4
	MOVD n+16(FP), R5
	CMP $0, R5
	BNE check
	RET

check:
	AND $~7, R5, R7     // R7 is N&~7.
	SUB R7, R5, R6      // R6 is N&7.

	// Copying forward proceeds by copying R7/8 words then copying R6 bytes.
	// R3 and R4 are advanced as we copy.

	// (There may be implementations of armv8 where copying by bytes until
	// at least one of source or dest is word aligned is a worthwhile
	// optimization, but the on the one tested so far (xgene) it did not
	// make a significance difference.)

	CMP $0, R7          // Do we need to do any word-by-word copying?
	BEQ noforwardlarge
	ADD R3, R7, R9      // R9 points just past where we copy by word.

forwardlargeloop:
	MOVD.P 8(R4), R8       // R8 is just a scratch register.
	MOVD.P R8, 8(R3)
	CMP R3, R9
	BNE forwardlargeloop

noforwardlarge:
	CMP $0, R6          // Do we need to do any byte-by-byte copying?
	BNE forwardtail
	RET

forwardtail:
	ADD R3, R6, R9      // R9 points just past the destination memory.

forwardtailloop:
	MOVBU.P 1(R4), R8
	MOVBU.P R8, 1(R3)
	CMP R3, R9
	BNE forwardtailloop
	RET
