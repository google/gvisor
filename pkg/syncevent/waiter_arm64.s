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

#include "textflag.h"

// See waiter_noasm_unsafe.go for a description of waiterUnlock.
//
// func waiterUnlock(g unsafe.Pointer, wg *unsafe.Pointer) bool
TEXT ·waiterUnlock(SB),NOSPLIT,$0-24
	MOVD wg+8(FP), R0
	MOVD $·preparingG(SB), R1
	MOVD g+0(FP), R2
again:
	LDAXR (R0), R3
	CMP R1, R3
	BNE ok
	STLXR R2, (R0), R3
	CBNZ R3, again
ok:
	CSET EQ, R0
	MOVB R0, ret+16(FP)
	RET

