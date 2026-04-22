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

//go:build riscv64
// +build riscv64

#include "textflag.h"

#define M_OFFSET      48 // +checkoffset runtime g.m
#define PROCID_OFFSET 72 // +checkoffset runtime m.procid

TEXT ·Current(SB),NOSPLIT,$0-8
	// procid is in getg().m.procid.
	MOV g, A0      // g
	MOV M_OFFSET(A0), A0 // gp.m
	MOV PROCID_OFFSET(A0), A0 // mp.procid
	MOV A0, ret+0(FP)
	RET
