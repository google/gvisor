// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

#include "textflag.h"

// All four primitives below use LL.W / SC.W (32-bit) or LL.D / SC.D
// (64-bit) load-linked / store-conditional pairs. We deliberately avoid
// the AM-family hardware atomics (AMSWAP.W, AMCAS.W, …) which require
// LoongArch v1.10 — Loongson-3A5000 implements only the v1.0 base ISA.
//
// In Go LoongArch asm the helper names are LL / LLV / SC / SCV (W / D).

// func swapUint32(ptr unsafe.Pointer, new uint32) (old uint32, sig int32)
TEXT ·swapUint32(SB), NOSPLIT, $0-24
	MOVV	ptr+0(FP), R4
	MOVW	new+8(FP), R5
swap32_loop:
	LL	(R4), R6              // faulting load-linked
	MOVW	R5, R7
	SC	R7, (R4)              // faulting store-conditional; R7=1 ok / 0 retry
	BEQ	R7, R0, swap32_loop
	MOVW	R6, old+16(FP)
	MOVW	R0, sig+20(FP)
	RET

TEXT handleSwapUint32Fault(SB), NOSPLIT, $0-24
	MOVW	R0, old+16(FP)
	MOVW	R5, sig+20(FP)
	RET

// func addrOfSwapUint32() uintptr
TEXT ·addrOfSwapUint32(SB), $0-8
	MOVV	$·swapUint32(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// func swapUint64(ptr unsafe.Pointer, new uint64) (old uint64, sig int32)
TEXT ·swapUint64(SB), NOSPLIT, $0-32
	MOVV	ptr+0(FP), R4
	MOVV	new+8(FP), R5
swap64_loop:
	LLV	(R4), R6              // faulting LL.D
	MOVV	R5, R7
	SCV	R7, (R4)              // faulting SC.D
	BEQ	R7, R0, swap64_loop
	MOVV	R6, old+16(FP)
	MOVW	R0, sig+24(FP)
	RET

TEXT handleSwapUint64Fault(SB), NOSPLIT, $0-32
	MOVV	R0, old+16(FP)
	MOVW	R5, sig+24(FP)
	RET

// func addrOfSwapUint64() uintptr
TEXT ·addrOfSwapUint64(SB), $0-8
	MOVV	$·swapUint64(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// func compareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (prev uint32, sig int32)
TEXT ·compareAndSwapUint32(SB), NOSPLIT, $0-24
	MOVV	ptr+0(FP), R4
	MOVW	old+8(FP), R5
	MOVW	new+12(FP), R6
cas_loop:
	LL	(R4), R7              // faulting LL.W
	BNE	R5, R7, cas_done      // mismatch: do not store
	MOVW	R6, R8
	SC	R8, (R4)
	BEQ	R8, R0, cas_loop      // SC failed -> retry
cas_done:
	MOVW	R7, prev+16(FP)
	MOVW	R0, sig+20(FP)
	RET

TEXT handleCompareAndSwapUint32Fault(SB), NOSPLIT, $0-24
	MOVW	R0, prev+16(FP)
	MOVW	R5, sig+20(FP)
	RET

// func addrOfCompareAndSwapUint32() uintptr
TEXT ·addrOfCompareAndSwapUint32(SB), $0-8
	MOVV	$·compareAndSwapUint32(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// func loadUint32(ptr unsafe.Pointer) (val uint32, sig int32)
TEXT ·loadUint32(SB), NOSPLIT, $0-16
	MOVV	ptr+0(FP), R4
	MOVW	(R4), R5              // faulting load
	MOVW	R5, val+8(FP)
	MOVW	R0, sig+12(FP)
	RET

TEXT handleLoadUint32Fault(SB), NOSPLIT, $0-16
	MOVW	R0, val+8(FP)
	MOVW	R5, sig+12(FP)
	RET

// func addrOfLoadUint32() uintptr
TEXT ·addrOfLoadUint32(SB), $0-8
	MOVV	$·loadUint32(SB), R4
	MOVV	R4, ret+0(FP)
	RET
