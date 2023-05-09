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

#define SYS_clock_gettime       113

TEXT ·vdsoClockGettime(SB), NOSPLIT, $0-24
	MOVW clockid+0(FP), R0
	MOVD ts+8(FP), R1
	MOVD runtime·vdsoClockgettimeSym(SB), R2
	CBZ R2, fallback
	BL (R2)
	MOVD R0, ret+16(FP)
	RET
fallback:
	MOVD $SYS_clock_gettime, R8
	SVC
	MOVD R0, ret+16(FP)
	RET
