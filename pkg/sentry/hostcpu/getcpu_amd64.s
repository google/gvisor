// Copyright 2018 Google LLC
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

// func GetCPU() (cpu uint32)
TEXT ·GetCPU(SB), NOSPLIT, $0-4
	BYTE $0x0f; BYTE $0x01; BYTE $0xf9; // RDTSCP
	// On Linux, the bottom 12 bits of IA32_TSC_AUX are CPU and the upper 20
	// are node. See arch/x86/entry/vdso/vma.c:vgetcpu_cpu_init().
	ANDL	$0xfff, CX
	MOVL	CX, cpu+0(FP)
	RET
