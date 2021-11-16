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

//go:build darwin && arm64
// +build darwin,arm64

#include "textflag.h"

TEXT libc_sigaction_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sigaction(SB)

GLOBL	·libc_sigaction_trampoline_addr(SB), RODATA, $8
DATA	·libc_sigaction_trampoline_addr(SB)/8, $libc_sigaction_trampoline<>(SB)
