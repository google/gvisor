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
	MOVQ g+0(FP), DI
	MOVQ wg+8(FP), SI

	MOVQ $·preparingG(SB), AX
	LOCK
	CMPXCHGQ DI, 0(SI)

	SETEQ AX
	MOVB AX, ret+16(FP)

	RET

