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
// +build loong64

#include "textflag.h"

// func Rdtsc() TSCValue
//
// LoongArch provides a 64-bit stable counter accessible from userspace via
// `rdtime.d rd, rj`. The counter ticks at a hardware-fixed frequency
// (100 MHz on 3A5000, ~125-150 MHz on 3A6000). The rj operand receives
// the counter ID into R0 (discarded); rd=R4 gets the value.
// Go reverses GNU operand order: `RDTIMED rj, rd` (matches runtime.cputicks).
TEXT ·Rdtsc(SB),NOSPLIT,$0-8
	RDTIMED	R0, R4
	MOVV	R4, ret+0(FP)
	RET
