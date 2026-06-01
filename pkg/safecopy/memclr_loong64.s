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

// func memclr(ptr uintptr, n uintptr) (fault uintptr, sig int32)
TEXT ·memclr(SB), NOSPLIT, $0-32
	MOVV	ptr+0(FP), R4
	MOVV	n+8(FP), R5
	BEQ	R5, R0, memclr_done
memclr_loop:
	MOVB	R0, (R4)           // faulting store
	ADDV	$1, R4, R4
	ADDV	$-1, R5, R5
	BNE	R5, R0, memclr_loop
memclr_done:
	MOVV	R0, fault+16(FP)
	MOVW	R0, sig+24(FP)
	RET

// handleMemclrFault: entered from signalHandler with
//   R4 = fault address
//   R5 = signal number
TEXT handleMemclrFault(SB), NOSPLIT, $0-32
	MOVV	R4, fault+16(FP)
	MOVW	R5, sig+24(FP)
	RET

// func addrOfMemclr() uintptr
TEXT ·addrOfMemclr(SB), $0-8
	MOVV	$·memclr(SB), R4
	MOVV	R4, ret+0(FP)
	RET
