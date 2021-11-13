// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

#include "textflag.h"

// handleMemclrFault returns (the value stored in R0, the value stored in R1).
// Control is transferred to it when memclr below receives SIGSEGV or SIGBUS,
// with the faulting address stored in R0 and the signal number stored in R1.
//
// It must have the same frame configuration as memclr so that it can undo any
// potential call frame set up by the assembler.
TEXT handleMemclrFault(SB), NOSPLIT, $0-28
	MOVD R0, addr+16(FP)
	MOVW R1, sig+24(FP)
	RET

// See the corresponding doc in safecopy_unsafe.go
//
// The code is derived from runtime.memclrNoHeapPointers.
//
// func memclr(ptr unsafe.Pointer, n uintptr) (fault unsafe.Pointer, sig int32)
TEXT ·memclr(SB), NOSPLIT, $0-28
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemclrFault will store a different value in this address.
	MOVW $0, sig+24(FP)
	MOVD ptr+0(FP), R0
	MOVD n+8(FP), R1

	// If size is less than 16 bytes, use tail_zero to zero what remains
	CMP $16, R1
	BLT tail_zero
	// Get buffer offset into 16 byte aligned address for better performance
	ANDS $15, R0, ZR
	BNE unaligned_to_16
aligned_to_16:
	LSR $4, R1, R2
zero_by_16:
	STP.P (ZR, ZR), 16(R0) // Store pair with post index.
	SUBS $1, R2, R2
	BNE zero_by_16
	ANDS $15, R1, R1
	BEQ end

	// Zero buffer with size=R1 < 16
tail_zero:
	TBZ $3, R1, tail_zero_4
	MOVD.P ZR, 8(R0)
tail_zero_4:
	TBZ $2, R1, tail_zero_2
	MOVW.P ZR, 4(R0)
tail_zero_2:
	TBZ $1, R1, tail_zero_1
	MOVH.P ZR, 2(R0)
tail_zero_1:
	TBZ $0, R1, end
	MOVB ZR, (R0)
end:
	RET

unaligned_to_16:
	MOVD R0, R2
head_loop:
	MOVBU.P ZR, 1(R0)
	ANDS $15, R0, ZR
	BNE head_loop
	// Adjust length for what remains
	SUB R2, R0, R3
	SUB R3, R1
	// If size is less than 16 bytes, use tail_zero to zero what remains
	CMP $16, R1
	BLT tail_zero
	B aligned_to_16

// func addrOfMemclr() uintptr
TEXT ·addrOfMemclr(SB), $0-8
	MOVD	$·memclr(SB), R0
	MOVD	R0, ret+0(FP)
	RET
