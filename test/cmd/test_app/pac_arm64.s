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

//go:build arm64
// +build arm64

#include "textflag.h"

// PACIA1716 and AUTIA1716 are HINT instructions, which execute as NOPs when
// pointer authentication is not in use.

// func pacia1716(ptr, modifier uint64) uint64
TEXT ·pacia1716(SB),NOSPLIT,$0-24
	MOVD	ptr+0(FP), R17
	MOVD	modifier+8(FP), R16
	WORD	$0xd503211f // PACIA1716
	MOVD	R17, ret+16(FP)
	RET

// func autia1716(ptr, modifier uint64) uint64
TEXT ·autia1716(SB),NOSPLIT,$0-24
	MOVD	ptr+0(FP), R17
	MOVD	modifier+8(FP), R16
	WORD	$0xd503219f // AUTIA1716
	MOVD	R17, ret+16(FP)
	RET
