// Copyright 2026 The gVisor Authors.
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

// func checkPAC() bool
//
// checkPAC signs the return address (R30/LR) with PACIASP and checks
// whether the value changed; if pointer authentication is not supported by
// the host CPU, PACIASP is a no-op HINT instruction and R30 is unchanged.
TEXT ·checkPAC(SB),NOSPLIT,$0-1
	MOVD	R30, R0			// Save LR
	WORD	$0xd503233f		// PACIASP (signs R30)
	CMP	R0, R30
	MOVD	$0, R1
	BEQ	same
	MOVD	$1, R1
same:
	MOVD	R0, R30			// Restore LR
	MOVB	R1, ret+0(FP)
	RET
