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

// KVM ioctls for Riscv64.
const (
	_KVM_GET_ONE_REG = 0x4010aeab
	_KVM_SET_ONE_REG = 0x4010aeac

	_KVM_RISCV64_REG_TYPE_SHIFT = 24
	_KVM_RISCV64_REGS_ISA	= 0x8030000001000000
	_KVM_RISCV64_REGS		= 0x8030000002000000
	_KVM_RISCV64_FPREGS	= 0x8030000006000000
	_KVM_RISCV64_FPREGS_FCSR	= 0x8020000006000020
	_KVM_RISCV64_REGS_CORE	= 0x02 << _KVM_RISCV64_REG_TYPE_SHIFT
	_KVM_RISCV64_REG_SIZE	= 1 << 6
	_KVM_RISCV64_REGS_PC	= 0x8030000002000000
	_KVM_RISCV64_REGS_SP	= 0x8030000002000002
	_KVM_RISCV64_REGS_TP	= 0x8030000002000004
	_KVM_RISCV64_REGS_SIE	= 0x8030000003000001
	_KVM_RISCV64_REGS_STVEC	= 0x8030000003000002
	_KVM_RISCV64_REGS_SEPC	= 0x8030000003000004
	_KVM_RISCV64_REGS_SATP	= 0x8030000003000008
	_KVM_RISCV64_REGS_SCAUSE = 0x8030000003000005
	_KVM_RISCV64_REGS_SSCRATCH = 0x8030000003000003

	_KVM_RISCV64_REGS_TIMER_CNT = 0x8030000004000001

	_KVM_RISCV64_REGS_FP	= 0x8030000006000000
	_KVM_RISCV64_REGS_FCSR	= 0x8030000006000020
)

// Riscv64: Supervisor Interrupt Enable register
const (
	_SIE_SSIE = 1 << 1
	_SIE_UTIE = 1 << 4
	//_SIE_SEIE = 1 << 9
	_SIE_UEIE = 1 << 8
	_SIE_VSIE = 1 << 10
	_SIE_DEFAULT = _SIE_SSIE | _SIE_UTIE | _SIE_UEIE | _SIE_VSIE
)

const (
	_KVM_EXIT_RISCV_SBI	= 35
)

const (
	// on Riscv64, the MMIO address must be 64-bit aligned.
	// Currently, we only need 1 hypercall: hypercall_vmexit.
	_RISCV64_HYPERCALL_MMIO_SIZE = 1 << 2
)

const (
	_RISCV64_ISA_MXL= 2 << 32
	_RISCV64_ISA_A	= 1 << 0
	_RISCV64_ISA_C	= 1 << 2
	_RISCV64_ISA_F	= 1 << 5
	_RISCV64_ISA_D	= 1 << 3
	_RISCV64_ISA_I	= 1 << 8
	_RISCV64_ISA_M	= 1 << 12
	_RISCV64_ISA_GC	= _RISCV64_ISA_A | _RISCV64_ISA_C | _RISCV64_ISA_D | _RISCV64_ISA_F | _RISCV64_ISA_I | _RISCV64_ISA_M 
)
