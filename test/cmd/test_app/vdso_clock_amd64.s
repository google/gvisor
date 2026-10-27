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

//go:build amd64
// +build amd64

#include "textflag.h"

// func callVDSOClockGettime(fn uintptr, clockid int32, ts uintptr) int32
TEXT ·callVDSOClockGettime(SB), NOSPLIT, $0-28
	MOVQ fn+0(FP), AX
	MOVL clockid+8(FP), DI
	MOVQ ts+16(FP), SI
	CALL AX
	MOVL AX, ret+24(FP)
	RET

// func rdtsc() uint64
TEXT ·rdtsc(SB), NOSPLIT, $0-8
	RDTSC
	SHLQ $32, DX
	ORQ DX, AX
	MOVQ AX, ret+0(FP)
	RET
