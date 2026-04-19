// Copyright 2020 The gVisor Authors.
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

#include "funcdata.h"
#include "textflag.h"

#define SATP_ASID_MASK 0xFFFF
#define SATP_ASID_SHIFT 44

// func GetASIDBits() uint8
TEXT ·GetASIDBits(SB)
	csrr t0, CSR_SATP
	li t1, (SATP_ASID_MASK << SATP_ASID_SHIFT)
	or t2, t0, t1
	csrw CSR_SATP, t2
	csrr t2, CSR_SATP
	srli t2, t2, SATP_ASID_SHIFT
	andi ra, t2, SATP_ASID_MASK
	RET
