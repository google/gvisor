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

//go:build amd64
// +build amd64

#include "textflag.h"

#define M_OFFSET       48 // +checkoffset runtime g.m
#define PROCID_OFFSET  72 // +checkoffset runtime m.procid

TEXT ·Current(SB),NOSPLIT|NOFRAME,$0-8
	// procid is in getg().m.procid.
	MOVQ TLS, AX
	MOVQ 0(AX)(TLS*1), AX
	MOVQ M_OFFSET(AX), AX // gp.m
	MOVQ PROCID_OFFSET(AX), AX // mp.procid
	MOVQ AX, ret+0(FP)
	RET
