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

#include "textflag.h"

// LoongArch could read the host's CPU number via `cpucfg $r12, $4` (word 4
// = stable-counter info) more cheaply, but for symmetry with arm64 we
// simply issue the getcpu(2) syscall.

// SYS_GETCPU = 168 (asm-generic numbering, identical to arm64).

// func GetCPU() uint32
TEXT ·GetCPU(SB), NOSPLIT, $0-4
	MOVW	R0, ret+0(FP)        // pre-zero the return slot
	MOVV	$ret+0(FP), R4       // &cpu
	MOVV	$0x0, R5             // node = NULL
	MOVV	$0x0, R6             // tcache = NULL (deprecated)
	MOVV	$168, R11            // SYS_GETCPU
	SYSCALL
	RET
