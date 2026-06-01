// Copyright 2024 The gVisor Authors.
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

//go:build loong64

#include "textflag.h"

#define M_OFFSET      {{ Offset (Import "runtime") "g.m" }}
#define PROCID_OFFSET {{ Offset (Import "runtime") "m.procid" }}

// func Current() uint64
//
// procid lives in `getg().m.procid` — same path as amd64 / arm64, only
// the register names change.
TEXT ·Current(SB),NOSPLIT,$0-8
	MOVV	g, R4                  // g
	MOVV	M_OFFSET(R4), R4       // gp.m
	MOVV	PROCID_OFFSET(R4), R4  // mp.procid
	MOVV	R4, ret+0(FP)
	RET
