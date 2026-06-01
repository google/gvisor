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

package cpuid

// HWCAP bits exposed to userspace via the auxiliary vector on LoongArch.
//
// See arch/loongarch/include/uapi/asm/hwcap.h in the Linux kernel.
const (
	HWCAP_LOONGARCH_CPUCFG   = 1 << 0
	HWCAP_LOONGARCH_LAM      = 1 << 1
	HWCAP_LOONGARCH_UAL      = 1 << 2
	HWCAP_LOONGARCH_FPU      = 1 << 3
	HWCAP_LOONGARCH_LSX      = 1 << 4
	HWCAP_LOONGARCH_LASX     = 1 << 5
	HWCAP_LOONGARCH_CRC32    = 1 << 6
	HWCAP_LOONGARCH_COMPLEX  = 1 << 7
	HWCAP_LOONGARCH_CRYPTO   = 1 << 8
	HWCAP_LOONGARCH_LVZ      = 1 << 9
	HWCAP_LOONGARCH_LBT_X86  = 1 << 10
	HWCAP_LOONGARCH_LBT_ARM  = 1 << 11
	HWCAP_LOONGARCH_LBT_MIPS = 1 << 12
	HWCAP_LOONGARCH_PTW      = 1 << 13
)
