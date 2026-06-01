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

// LoongArch64 register conventions used below (Go asm):
//   R4 = a0 = arg0 / return0
//   R5 = a1 = arg1 / return1
//   R6 = a2 = arg2
//   R7..R10 = temporaries (callee-clobber, safe for NOSPLIT funcs)
//   R0 = hard-wired zero
//
// The handle*Fault stubs are entered by signalHandler() after it has
// installed (via ucontext) R4 = faulting address and R5 = signal number.

// func memcpy(dst, src uintptr, n uintptr) (fault uintptr, sig int32)
TEXT ·memcpy(SB), NOSPLIT, $0-40
	MOVV	dst+0(FP), R4
	MOVV	src+8(FP), R5
	MOVV	n+16(FP), R6
	BEQ	R6, R0, memcpy_done
memcpy_loop:
	MOVB	(R5), R7           // faulting load
	MOVB	R7, (R4)           // faulting store
	ADDV	$1, R4, R4
	ADDV	$1, R5, R5
	ADDV	$-1, R6, R6
	BNE	R6, R0, memcpy_loop
memcpy_done:
	MOVV	R0, fault+24(FP)
	MOVW	R0, sig+32(FP)
	RET

// handleMemcpyFault: entered from signalHandler with
//   R4 = fault address
//   R5 = signal number
TEXT handleMemcpyFault(SB), NOSPLIT, $0-40
	MOVV	R4, fault+24(FP)
	MOVW	R5, sig+32(FP)
	RET

// func addrOfMemcpy() uintptr
TEXT ·addrOfMemcpy(SB), $0-8
	MOVV	$·memcpy(SB), R4
	MOVV	R4, ret+0(FP)
	RET
