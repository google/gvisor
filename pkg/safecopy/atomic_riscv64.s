// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// handleSwapUint32Fault returns the value stored in R1. Control is transferred
// to it when swapUint32 below receives SIGSEGV or SIGBUS, with the signal
// number stored in R1.
//
// It must have the same frame configuration as swapUint32 so that it can undo
// any potential call frame set up by the assembler.
TEXT handleSwapUint32Fault(SB), NOSPLIT, $0-24
	MOVW A1, sig+20(FP)
	RET

// See the corresponding doc in safecopy_unsafe.go
//
// The code is derived from Go source runtime/internal/atomic.Xchg.
//
//func swapUint32(ptr unsafe.Pointer, new uint32) (old uint32, sig int32)
TEXT ·swapUint32(SB), NOSPLIT, $0-24
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleSwapUint32Fault will store a different value in this address.
	MOVW	ZERO, sig+20(FP)
	MOV	ptr+0(FP), A0
	MOVW	new+8(FP), A1
	AMOSWAPW A1, (A0), A1
	MOVW	A1, old+16(FP)
	RET

// func addrOfSwapUint32() uintptr
TEXT ·addrOfSwapUint32(SB), $0-8
	MOV	$·swapUint32(SB), A0
	MOV	A0, ret+0(FP)
	RET

// handleSwapUint64Fault returns the value stored in R1. Control is transferred
// to it when swapUint64 below receives SIGSEGV or SIGBUS, with the signal
// number stored in R1.
//
// It must have the same frame configuration as swapUint64 so that it can undo
// any potential call frame set up by the assembler.
TEXT handleSwapUint64Fault(SB), NOSPLIT, $0-28
	MOVW  A1, sig+24(FP)
	RET

// See the corresponding doc in safecopy_unsafe.go
//
// The code is derived from Go source runtime/internal/atomic.Xchg64.
//
//func swapUint64(ptr unsafe.Pointer, new uint64) (old uint64, sig int32)
TEXT ·swapUint64(SB), NOSPLIT, $0-28
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleSwapUint64Fault will store a different value in this address.
	MOVW	ZERO, sig+24(FP)
	MOV	ptr+0(FP), A0
	MOV	new+8(FP), A1
	AMOSWAPD A1, (A0), A1
	MOV	A1, old+16(FP)
	RET

// func addrOfSwapUint64() uintptr
TEXT ·addrOfSwapUint64(SB), $0-8
	MOV	$·swapUint64(SB), A0
	MOV	A0, ret+0(FP)
	RET

// handleCompareAndSwapUint32Fault returns the value stored in A0. Control is
// transferred to it when compareAndSwapUint32 below receives SIGSEGV or SIGBUS,
// with the signal number stored in R1.
//
// It must have the same frame configuration as compareAndSwapUint32 so that it
// can undo any potential call frame set up by the assembler.
TEXT handleCompareAndSwapUint32Fault(SB), NOSPLIT, $0-24
	MOVW A1, sig+20(FP)
	RET

// See the corresponding doc in safecopy_unsafe.go
//
// The code is derived from Go source runtime/internal/atomic.Cas.
//
//func compareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (prev uint32, sig int32)
TEXT ·compareAndSwapUint32(SB), NOSPLIT, $0-24
	// Store 0 as the returned signal number. If we run to completion, this is
	// the value the caller will see; if a signal is received,
	// handleCompareAndSwapUint32Fault will store a different value in this
	// address.
	MOVW	ZERO, sig+20(FP)

	MOV	ptr+0(FP), A0
	MOVW	old+8(FP), A1
	MOVW	new+12(FP), A2
cas_again:
	LRW	(A0), A3
	BNE	A3, A1, cas_fail
	SCW	A2, (A0), A4
	BNE	A4, ZERO, cas_again
	MOVW	A3, prev+16(FP)
	RET
cas_fail:
	MOVW	A3, prev+16(FP)
	RET

// func addrOfCompareAndSwapUint32() uintptr
TEXT ·addrOfCompareAndSwapUint32(SB), $0-8
	MOV	$·compareAndSwapUint32(SB), A0
	MOV	A0, ret+0(FP)
	RET

// handleLoadUint32Fault returns the value stored in DI. Control is transferred
// to it when LoadUint32 below receives SIGSEGV or SIGBUS, with the signal
// number stored in A1.
//
// It must have the same frame configuration as loadUint32 so that it can undo
// any potential call frame set up by the assembler.
TEXT handleLoadUint32Fault(SB), NOSPLIT, $0-16
	MOVW  A1, sig+12(FP)
	RET

// loadUint32 atomically loads *ptr and returns it. If a SIGSEGV or SIGBUS
// signal is received, the value returned is unspecified, and sig is the number
// of the signal that was received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//func loadUint32(ptr unsafe.Pointer) (val uint32, sig int32)
TEXT ·loadUint32(SB), NOSPLIT, $0-16
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleLoadUint32Fault will store a different value in this address.
	MOVW 	ZERO, sig+12(FP)

	MOV	ptr+0(FP), A0
	LRW	(A0), A1
	MOVW	A1, val+8(FP)
	RET

// func addrOfLoadUint32() uintptr
TEXT ·addrOfLoadUint32(SB), $0-8
	MOV	$·loadUint32(SB), A0
	MOV	A0, ret+0(FP)
	RET
