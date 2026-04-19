// Copyright 2019 The gVisor Authors.
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

// GetCPU makes the getcpu(unsigned *cpu, unsigned *node, NULL) syscall for
// the lack of an optimazed way of getting the current CPU number on arm64.

// func GetCPU() uint32
TEXT ·GetCPU(SB), NOSPLIT, $0-4
	MOVW ZERO, ret+0(FP)
	MOV $ret+0(FP), A0
	MOV $0x0, A1  // unused
	MOV $0x0, A2  // unused
	MOV $0xA8, A7 // SYS_GETCPU
	ECALL
	RET
