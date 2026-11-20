// Copyright 2014 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

#include "textflag.h"

// handleMemclrFault returns (the value stored in R0, the value stored in R1),
// or restarts memclr. Control is transferred to it when memclr below receives
// SIGSEGV or SIGBUS, with the faulting address stored in R0 and the signal
// number stored in R1.
//
// It must have the same frame configuration as memclr so that it can undo any
// potential call frame set up by the assembler.
TEXT handleMemclrFault(SB), NOSPLIT|NOFRAME, $0-36
	// If DC ZVA faulted, R5 is non-zero, everything before R3 has been
	// written, and R6 is the end of the range. DC ZVA cannot write Device
	// memory, which other stores can, so restart from R3 with fast set to
	// false.
	CBNZ R5, restart
	MOVD R0, addr+24(FP)
	MOVW R1, sig+32(FP)
	RET
restart:
	MOVD R3, ptr+0(FP)
	SUB R3, R6, R3
	MOVD R3, n+8(FP)
	MOVB ZR, fast+16(FP)
	B ·memclr(SB)

// See the corresponding doc in safecopy_unsafe.go
//
// The code is derived from runtime.memclrNoHeapPointers.
//
// func memclr(ptr unsafe.Pointer, n uintptr, fast bool) (fault unsafe.Pointer, sig int32)
TEXT ·memclr(SB), NOSPLIT|NOFRAME, $0-36
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemclrFault will store a different value in this address.
	MOVW $0, sig+32(FP)
	MOVD ptr+0(FP), R0
	MOVD n+8(FP), R1
	MOVD ZR, R5

	// Like the runtime's memclr, zero whole 64-byte blocks of large ranges
	// with DC ZVA if it is allowed.
	MOVBU fast+16(FP), R2
	CBZ R2, plain
	MOVBU ·useZVA(SB), R2
	CBZ R2, plain
	CMP $256, R1
	BLO plain
	ADD R0, R1, R6
	SUB $64, R6, R7
	MOVD R0, R3
	MOVD $1, R5
	ANDS $63, R0, ZR
	BEQ zva_loop
	STP (ZR, ZR), (R0)
	STP (ZR, ZR), 16(R0)
	STP (ZR, ZR), 32(R0)
	STP (ZR, ZR), 48(R0)
	ADD $64, R0, R3
	AND $~63, R3, R3
	PCALIGN $16
zva_loop:
	DC ZVA, R3
	ADD $64, R3, R3
	CMP R7, R3
	BLS zva_loop
	MOVD ZR, R5
	MOVD R3, R0
	SUBS R3, R6, R1
	BEQ end

plain:
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

// func dczid() uint64
TEXT ·dczid(SB), NOSPLIT, $0-8
	MRS DCZID_EL0, R0
	MOVD R0, ret+0(FP)
	RET

// func addrOfMemclr() uintptr
TEXT ·addrOfMemclr(SB), $0-8
	MOVD	$·memclr(SB), R0
	MOVD	R0, ret+0(FP)
	RET
