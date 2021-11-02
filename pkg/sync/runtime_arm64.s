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

//go:build arm64 && go1.8 && !go1.19 && !goexperiment.staticlockranking
// +build arm64,go1.8,!go1.19,!goexperiment.staticlockranking

#include "textflag.h"

TEXT ·addrOfSpinning(SB),NOSPLIT,$0-8
	// The offset specified here is the nmspinning value in sched.
	MOVD $runtime·sched(SB), R0
	MOVQ $92, R1
	ADDQ R0, R1, R0
	MOVD R0, ret+0(FP)
	RET
