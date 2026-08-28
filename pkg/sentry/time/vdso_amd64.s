// Copyright 2021 The gVisor Authors.
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

#define SYS_clock_gettime       228

TEXT ·vdsoClockGettime(SB),NOSPLIT|NOFRAME,$0-24
	MOVL clockid+0(FP), DI
	MOVQ ts+8(FP), SI
	MOVQ runtime·vdsoClockgettimeSym(SB), AX
	CMPQ AX, $0
	JEQ fallback

	// When TSC offset is active, host VDSO cannot be called in GR0 because
	// guest RDTSC includes the offset. Transition to HR3 (redpill).
	MOVQ ·tscOffset(SB), BX
	CMPQ BX, $0
	JEQ call_vdso
	MOVW CS, BX
	ANDW $3, BX
	JNE call_vdso

	// Fallback to HR3.
	MOVQ $-1, AX
	SYSCALL
	MOVL clockid+0(FP), DI
	MOVQ ts+8(FP), SI
	MOVQ runtime·vdsoClockgettimeSym(SB), AX

call_vdso:
	CALL AX
	MOVQ AX, ret+16(FP)
	RET
fallback:
	MOVQ $SYS_clock_gettime, AX
	SYSCALL
	MOVQ AX, ret+16(FP)
	RET

