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

// func callVDSOClockGettime(fn uintptr, clockid int32, ts uintptr) int32
TEXT ·callVDSOClockGettime(SB), NOSPLIT, $0-28
	MOVD fn+0(FP), R2
	MOVW clockid+8(FP), R0
	MOVD ts+16(FP), R1
	BL (R2)
	MOVW R0, ret+24(FP)
	RET

// func rdtsc() uint64
TEXT ·rdtsc(SB), NOSPLIT, $0-8
	ISB $15
	MRS CNTVCT_EL0, R0
	MOVD R0, ret+0(FP)
	RET
