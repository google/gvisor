// Copyright 2020 The gVisor Authors.
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

//go:build race && riscv64
// +build race,riscv64

#include "textflag.h"

// func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool
TEXT ·RaceUncheckedAtomicCompareAndSwapUintptr(SB),NOSPLIT,$0-25
	MOV ptr+0(FP), A0
	MOV old+8(FP), A1
	MOV new+16(FP), A2

cas_again:
	LRD	(A0), A3
	BNE	A3, A1, cas_fail
	SCD	A2, (A0), A4
	BNE	A4, ZERO, cas_again
	MOV	$1, A0
	MOVB	A0, ret+24(FP)
	RET
cas_fail:
	MOVB	ZERO, ret+24(FP)
	RET
