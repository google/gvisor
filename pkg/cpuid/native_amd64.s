// Copyright 2018 The gVisor Authors.
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

TEXT ·native(SB),NOSPLIT|NOFRAME,$0-24
	MOVL arg_Eax+0(FP), AX
	MOVL arg_Ecx+4(FP), CX
	CPUID
	MOVL AX, ret_Eax+8(FP)
	MOVL BX, ret_Ebx+12(FP)
	MOVL CX, ret_Ecx+16(FP)
	MOVL DX, ret_Edx+20(FP)
	RET

// xgetbv reads an extended control register.
//
// The code corresponds to:
//
// 	xgetbv
//
TEXT ·xgetbv(SB),NOSPLIT|NOFRAME,$0-16
	MOVQ reg+0(FP), CX
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0;
	MOVL AX, ret+8(FP)
	MOVL DX, ret+12(FP)
	RET
