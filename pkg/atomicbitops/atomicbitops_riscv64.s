// Copyright 2019 The gVisor Authors.
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

// +build riscv64

#include "textflag.h"

TEXT ·andUint32(SB),NOSPLIT,$0-12
	MOV	addr+0(FP), A0
	MOVW	val+8(FP), A1
	AMOANDW	A1, (A0), ZERO
  	RET

TEXT ·orUint32(SB),NOSPLIT,$0-12
	MOV	ptr+0(FP), A0
	MOVW	val+8(FP), A1
	AMOORW	A1, (A0), ZERO
	RET

TEXT ·xorUint32(SB),NOSPLIT,$0-12
	MOV	addr+0(FP), A0
	MOV	val+8(FP), A1
	AMOXORW	A1, (A0), ZERO
	RET

TEXT ·compareAndSwapUint32(SB),NOSPLIT,$0-20
	MOV	addr+0(FP), A0
	MOVW	old+8(FP), A1
	MOVW	new+12(FP), A2
cas_again:
	LRW	(A0), A3
	BNE	A3, A1, cas_fail
	SCW	A2, (A0), A4
	BNE	A4, ZERO, cas_again
	MOVW	A3, ret+16(FP)
	RET
cas_fail:
	MOVW	A3, ret+16(FP)
	RET

TEXT ·andUint64(SB),NOSPLIT,$0-16
	MOV	addr+0(FP), A0
	MOV	val+8(FP), A1
	AMOANDD	A1, (A0), ZERO
	RET

TEXT ·orUint64(SB),NOSPLIT,$0-16
	MOV	addr+0(FP), A0
	MOV	val+8(FP), A1
	AMOORD	A1, (A0), ZERO
	RET

TEXT ·xorUint64(SB),NOSPLIT,$0-16
	MOV	addr+0(FP), A0
	MOV	val+8(FP), A1
	AMOXORD	A1, (A0), ZERO
	RET

TEXT ·compareAndSwapUint64(SB),NOSPLIT,$0-32
	MOV	addr+0(FP), A0
	MOV	old+8(FP), A1
	MOV	new+16(FP), A2
cas_again:
	LRD	(A0), A3
	BNE	A3, A1, cas_fail
	SCD	A2, (A0), A4
	BNE	A4, ZERO, cas_again
	MOV	A3, ret+24(FP)
	RET
cas_fail:
	MOV	A3, ret+24(FP)
	RET	
