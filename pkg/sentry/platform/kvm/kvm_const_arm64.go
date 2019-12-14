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

package kvm

// KVM ioctls for Arm64.
const (
	_KVM_GET_ONE_REG = 0x4010aeab
	_KVM_SET_ONE_REG = 0x4010aeac

	_KVM_ARM_PREFERRED_TARGET = 0x8020aeaf
	_KVM_ARM_VCPU_INIT        = 0x4020aeae
	_KVM_ARM64_REGS_PSTATE    = 0x6030000000100042
	_KVM_ARM64_REGS_SP_EL1    = 0x6030000000100044
	_KVM_ARM64_REGS_R0        = 0x6030000000100000
	_KVM_ARM64_REGS_R1        = 0x6030000000100002
	_KVM_ARM64_REGS_R2        = 0x6030000000100004
	_KVM_ARM64_REGS_R3        = 0x6030000000100006
	_KVM_ARM64_REGS_R8        = 0x6030000000100010
	_KVM_ARM64_REGS_R18       = 0x6030000000100024
	_KVM_ARM64_REGS_PC        = 0x6030000000100040
	_KVM_ARM64_REGS_MAIR_EL1  = 0x603000000013c510
	_KVM_ARM64_REGS_TCR_EL1   = 0x603000000013c102
	_KVM_ARM64_REGS_TTBR0_EL1 = 0x603000000013c100
	_KVM_ARM64_REGS_TTBR1_EL1 = 0x603000000013c101
	_KVM_ARM64_REGS_SCTLR_EL1 = 0x603000000013c080
	_KVM_ARM64_REGS_CPACR_EL1 = 0x603000000013c082
	_KVM_ARM64_REGS_VBAR_EL1  = 0x603000000013c600
)

// Arm64: Architectural Feature Access Control Register EL1.
const (
	_FPEN_NOTRAP = 0x3
	_FPEN_SHIFT  = 0x20
)

// Arm64: System Control Register EL1.
const (
	_SCTLR_M = 1 << 0
	_SCTLR_C = 1 << 2
	_SCTLR_I = 1 << 12
)

// Arm64: Translation Control Register EL1.
const (
	_TCR_IPS_40BITS = 2 << 32 // PA=40
	_TCR_IPS_48BITS = 5 << 32 // PA=48

	_TCR_T0SZ_OFFSET = 0
	_TCR_T1SZ_OFFSET = 16
	_TCR_IRGN0_SHIFT = 8
	_TCR_IRGN1_SHIFT = 24
	_TCR_ORGN0_SHIFT = 10
	_TCR_ORGN1_SHIFT = 26
	_TCR_SH0_SHIFT   = 12
	_TCR_SH1_SHIFT   = 28
	_TCR_TG0_SHIFT   = 14
	_TCR_TG1_SHIFT   = 30

	_TCR_T0SZ_VA48 = 64 - 48 // VA=48
	_TCR_T1SZ_VA48 = 64 - 48 // VA=48

	_TCR_ASID16 = 1 << 36
	_TCR_TBI0   = 1 << 37

	_TCR_TXSZ_VA48 = (_TCR_T0SZ_VA48 << _TCR_T0SZ_OFFSET) | (_TCR_T1SZ_VA48 << _TCR_T1SZ_OFFSET)

	_TCR_TG0_4K  = 0 << _TCR_TG0_SHIFT // 4K
	_TCR_TG0_64K = 1 << _TCR_TG0_SHIFT // 64K

	_TCR_TG1_4K = 2 << _TCR_TG1_SHIFT

	_TCR_TG_FLAGS = _TCR_TG0_4K | _TCR_TG1_4K

	_TCR_IRGN0_WBWA = 1 << _TCR_IRGN0_SHIFT
	_TCR_IRGN1_WBWA = 1 << _TCR_IRGN1_SHIFT
	_TCR_IRGN_WBWA  = _TCR_IRGN0_WBWA | _TCR_IRGN1_WBWA

	_TCR_ORGN0_WBWA = 1 << _TCR_ORGN0_SHIFT
	_TCR_ORGN1_WBWA = 1 << _TCR_ORGN1_SHIFT

	_TCR_ORGN_WBWA = _TCR_ORGN0_WBWA | _TCR_ORGN1_WBWA

	_TCR_SHARED = (3 << _TCR_SH0_SHIFT) | (3 << _TCR_SH1_SHIFT)

	_TCR_CACHE_FLAGS = _TCR_IRGN_WBWA | _TCR_ORGN_WBWA
)

// Arm64: Memory Attribute Indirection Register EL1.
const (
	_MT_DEVICE_nGnRnE = 0
	_MT_DEVICE_nGnRE  = 1
	_MT_DEVICE_GRE    = 2
	_MT_NORMAL_NC     = 3
	_MT_NORMAL        = 4
	_MT_NORMAL_WT     = 5
	_MT_EL1_INIT      = (0 << _MT_DEVICE_nGnRnE) | (0x4 << _MT_DEVICE_nGnRE * 8) | (0xc << _MT_DEVICE_GRE * 8) | (0x44 << _MT_NORMAL_NC * 8) | (0xff << _MT_NORMAL * 8) | (0xbb << _MT_NORMAL_WT * 8)
)

const (
	_KVM_ARM_VCPU_POWER_OFF = 0 // CPU is started in OFF state
	_KVM_ARM_VCPU_PSCI_0_2  = 2 // CPU uses PSCI v0.2
)

// Arm64: Exception Syndrome Register EL1.
const (
	_ESR_ELx_FSC = 0x3F

	_ESR_SEGV_MAPERR_L0 = 0x4
	_ESR_SEGV_MAPERR_L1 = 0x5
	_ESR_SEGV_MAPERR_L2 = 0x6
	_ESR_SEGV_MAPERR_L3 = 0x7

	_ESR_SEGV_ACCERR_L1 = 0x9
	_ESR_SEGV_ACCERR_L2 = 0xa
	_ESR_SEGV_ACCERR_L3 = 0xb

	_ESR_SEGV_PEMERR_L1 = 0xd
	_ESR_SEGV_PEMERR_L2 = 0xe
	_ESR_SEGV_PEMERR_L3 = 0xf
)
