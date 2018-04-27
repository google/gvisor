// Copyright 2018 Google Inc.
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

TEXT ·Rdtsc(SB),NOSPLIT,$0-8
	// N.B. We need LFENCE on Intel, AMD is more complicated.
	// Modern AMD CPUs with modern kernels make LFENCE behave like it does
	// on Intel with MSR_F10H_DECFG_LFENCE_SERIALIZE_BIT. MFENCE is
	// otherwise needed on AMD.
	LFENCE
	RDTSC
	SHLQ	$32, DX
	ADDQ	DX, AX
	MOVQ	AX, ret+0(FP)
	RET
