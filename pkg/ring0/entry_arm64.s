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

#include "funcdata.h"
#include "textflag.h"

#define CPU_SELF             {{ .CPU.self.Offset }}
#define CPU_REGISTERS        {{ .CPU.registers.Offset }}
#define CPU_STACK_TOP        ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.stack.Offset }} + {{ .CPUArchState.stack.Size }})
#define CPU_ERROR_CODE       ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.errorCode.Offset }})
#define CPU_ERROR_TYPE       ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.errorType.Offset }})
#define CPU_FAULT_ADDR       ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.faultAddr.Offset }})
#define CPU_FPSTATE_EL0      ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.el0Fp.Offset }})
#define CPU_TTBR0_KVM       ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.ttbr0Kvm.Offset }})
#define CPU_TTBR0_APP        ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.ttbr0App.Offset }})
#define CPU_VECTOR_CODE      ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.vecCode.Offset }})
#define CPU_APP_ADDR         ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.appAddr.Offset }})
#define CPU_LAZY_VFP         ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.lazyVFP.Offset }})
#define CPU_APP_ASID         ({{ .CPU.CPUArchState.Offset }}+{{ .CPUArchState.appASID.Offset }})

// Bits.
#define _KERNEL_FLAGS {{ .KernelFlagsSet.Value }}

// Vectors.
#define El1Sync                 {{ .El1Sync.Value }}
#define El1Irq                  {{ .El1Irq.Value }}
#define El1Fiq                  {{ .El1Fiq.Value }}
#define El1Err                  {{ .El1Err.Value }}
#define El0Sync                 {{ .El0Sync.Value }}
#define El0Irq                  {{ .El0Irq.Value }}
#define El0Fiq                  {{ .El0Fiq.Value }}
#define El0Err                  {{ .El0Err.Value }}
#define El1SyncDa               {{ .El1SyncDa.Value }}
#define El1SyncIa               {{ .El1SyncIa.Value }}
#define El1SyncSpPc             {{ .El1SyncSpPc.Value }}
#define El1SyncUndef            {{ .El1SyncUndef.Value }}
#define El1SyncDbg              {{ .El1SyncDbg.Value }}
#define El1SyncInv              {{ .El1SyncInv.Value }}
#define El0SyncSVC              {{ .El0SyncSVC.Value }}
#define El0SyncDa               {{ .El0SyncDa.Value }}
#define El0SyncIa               {{ .El0SyncIa.Value }}
#define El0SyncFpsimdAcc        {{ .El0SyncFpsimdAcc.Value }}
#define El0SyncSveAcc           {{ .El0SyncSveAcc.Value }}
#define El0SyncFpsimdExc        {{ .El0SyncFpsimdExc.Value }}
#define El0SyncSys              {{ .El0SyncSys.Value }}
#define El0SyncSpPc             {{ .El0SyncSpPc.Value }}
#define El0SyncUndef            {{ .El0SyncUndef.Value }}
#define El0SyncDbg              {{ .El0SyncDbg.Value }}
#define El0SyncWfx              {{ .El0SyncWfx.Value }}
#define El0SyncInv              {{ .El0SyncInv.Value }}
#define El0ErrNMI               {{ .El0ErrNMI.Value }}
#define PageFault               {{ .PageFault.Value }}
#define Syscall                 {{ .Syscall.Value }}
#define VirtualizationException {{ .VirtualizationException.Value }}

{{ with .import.linux.PtraceRegs }}
#define PTRACE_R0       ({{ .Regs.Offset }} + 0*8)
#define PTRACE_R1       ({{ .Regs.Offset }} + 1*8)
#define PTRACE_R2       ({{ .Regs.Offset }} + 2*8)
#define PTRACE_R3       ({{ .Regs.Offset }} + 3*8)
#define PTRACE_R4       ({{ .Regs.Offset }} + 4*8)
#define PTRACE_R5       ({{ .Regs.Offset }} + 5*8)
#define PTRACE_R6       ({{ .Regs.Offset }} + 6*8)
#define PTRACE_R7       ({{ .Regs.Offset }} + 7*8)
#define PTRACE_R8       ({{ .Regs.Offset }} + 8*8)
#define PTRACE_R9       ({{ .Regs.Offset }} + 9*8)
#define PTRACE_R10      ({{ .Regs.Offset }} + 10*8)
#define PTRACE_R11      ({{ .Regs.Offset }} + 11*8)
#define PTRACE_R12      ({{ .Regs.Offset }} + 12*8)
#define PTRACE_R13      ({{ .Regs.Offset }} + 13*8)
#define PTRACE_R14      ({{ .Regs.Offset }} + 14*8)
#define PTRACE_R15      ({{ .Regs.Offset }} + 15*8)
#define PTRACE_R16      ({{ .Regs.Offset }} + 16*8)
#define PTRACE_R17      ({{ .Regs.Offset }} + 17*8)
#define PTRACE_R18      ({{ .Regs.Offset }} + 18*8)
#define PTRACE_R19      ({{ .Regs.Offset }} + 19*8)
#define PTRACE_R20      ({{ .Regs.Offset }} + 20*8)
#define PTRACE_R21      ({{ .Regs.Offset }} + 21*8)
#define PTRACE_R22      ({{ .Regs.Offset }} + 22*8)
#define PTRACE_R23      ({{ .Regs.Offset }} + 23*8)
#define PTRACE_R24      ({{ .Regs.Offset }} + 24*8)
#define PTRACE_R25      ({{ .Regs.Offset }} + 25*8)
#define PTRACE_R26      ({{ .Regs.Offset }} + 26*8)
#define PTRACE_R27      ({{ .Regs.Offset }} + 27*8)
#define PTRACE_R28      ({{ .Regs.Offset }} + 28*8)
#define PTRACE_R29      ({{ .Regs.Offset }} + 29*8)
#define PTRACE_R30      ({{ .Regs.Offset }} + 30*8)
#define PTRACE_SP       {{ .Sp.Offset }}
#define PTRACE_PC       {{ .Pc.Offset }}
#define PTRACE_PSTATE   {{ .Pstate.Offset }}
{{ end }}
{{ with .import.arch.Registers }}
#define PTRACE_TLS      {{ .TPIDR_EL0.Offset }}
{{ end }}

// Saves a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//

// ERET returns using the ELR and SPSR for the current exception level.
#define ERET() \
  WORD $0xd69f03e0; \
  DSB $7; \
  ISB $15;

// RSV_REG is a register that holds el1 information temporarily.
#define RSV_REG 	R18_PLATFORM

// RSV_REG_APP is a register that holds el0 information temporarily.
#define RSV_REG_APP 	R19

#define FPEN_NOTRAP 	0x3
#define FPEN_SHIFT 	20

#define FPEN_ENABLE (FPEN_NOTRAP << FPEN_SHIFT)

// sctlr_el1: system control register el1.
#define SCTLR_M         1 << 0
#define SCTLR_C         1 << 2
#define SCTLR_I         1 << 12
#define SCTLR_DZE       1 << 14
#define SCTLR_UCT       1 << 15
#define SCTLR_UCI       1 << 26

#define SCTLR_EL1_DEFAULT       (SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_UCT | SCTLR_UCI | SCTLR_DZE)

// cntkctl_el1: counter-timer kernel control register el1.
#define CNTKCTL_EL0PCTEN 	1 << 0
#define CNTKCTL_EL0VCTEN 	1 << 1

#define CNTKCTL_EL1_DEFAULT 	(CNTKCTL_EL0PCTEN | CNTKCTL_EL0VCTEN)

// Saves a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
// The following registers are not saved: R18, R19.
#define REGISTERS_SAVE(reg, offset) \
  STP (R0, R1), offset+PTRACE_R0(reg); \
  STP (R2, R3), offset+PTRACE_R2(reg); \
  STP (R4, R5), offset+PTRACE_R4(reg); \
  STP (R6, R7), offset+PTRACE_R6(reg); \
  STP (R8, R9), offset+PTRACE_R8(reg); \
  STP (R10, R11), offset+PTRACE_R10(reg); \
  STP (R12, R13), offset+PTRACE_R12(reg); \
  STP (R14, R15), offset+PTRACE_R14(reg); \
  STP (R16, R17), offset+PTRACE_R16(reg); \
  STP (R20, R21), offset+PTRACE_R20(reg); \
  STP (R22, R23), offset+PTRACE_R22(reg); \
  STP (R24, R25), offset+PTRACE_R24(reg); \
  STP (R26, R27), offset+PTRACE_R26(reg); \
  STP (g, R29), offset+PTRACE_R28(reg); \
  MOVD R30, offset+PTRACE_R30(reg);

// Loads a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
// The following registers are not loaded: R18, R19.
#define REGISTERS_LOAD(reg, offset) \
  LDP offset+PTRACE_R0(reg), (R0, R1); \
  LDP offset+PTRACE_R2(reg), (R2, R3); \
  LDP offset+PTRACE_R4(reg), (R4, R5); \
  LDP offset+PTRACE_R6(reg), (R6, R7); \
  LDP offset+PTRACE_R8(reg), (R8, R9); \
  LDP offset+PTRACE_R10(reg), (R10, R11); \
  LDP offset+PTRACE_R12(reg), (R12, R13); \
  LDP offset+PTRACE_R14(reg), (R14, R15); \
  LDP offset+PTRACE_R16(reg), (R16, R17); \
  LDP offset+PTRACE_R20(reg), (R20, R21); \
  LDP offset+PTRACE_R22(reg), (R22, R23); \
  LDP offset+PTRACE_R24(reg), (R24, R25); \
  LDP offset+PTRACE_R26(reg), (R26, R27); \
  LDP offset+PTRACE_R28(reg), (g, R29); \
  MOVD offset+PTRACE_R30(reg), R30;

// Loads the application's fpstate.
#define FPSTATE_EL0_LOAD() \
  MRS TPIDR_EL1, RSV_REG; \
  MOVD CPU_FPSTATE_EL0(RSV_REG), RSV_REG; \
  MOVD 0(RSV_REG), RSV_REG_APP; \
  MOVD RSV_REG_APP, FPSR; \
  MOVD 8(RSV_REG), RSV_REG_APP; \
  MOVD RSV_REG_APP, FPCR; \
  ADD $16, RSV_REG, RSV_REG; \
  WORD $0xad400640; \ // ldp q0, q1, [x18]
  WORD $0xad410e42; \
  WORD $0xad421644; \
  WORD $0xad431e46; \
  WORD $0xad442648; \
  WORD $0xad452e4a; \
  WORD $0xad46364c; \
  WORD $0xad473e4e; \
  WORD $0xad484650; \
  WORD $0xad494e52; \
  WORD $0xad4a5654; \
  WORD $0xad4b5e56; \
  WORD $0xad4c6658; \
  WORD $0xad4d6e5a; \
  WORD $0xad4e765c; \
  WORD $0xad4f7e5e;

#define ESR_ELx_EC_UNKNOWN	(0x00)
#define ESR_ELx_EC_WFx		(0x01)
/* Unallocated EC: 0x02 */
#define ESR_ELx_EC_CP15_32	(0x03)
#define ESR_ELx_EC_CP15_64	(0x04)
#define ESR_ELx_EC_CP14_MR	(0x05)
#define ESR_ELx_EC_CP14_LS	(0x06)
#define ESR_ELx_EC_FP_ASIMD	(0x07)
#define ESR_ELx_EC_CP10_ID	(0x08)	/* EL2 only */
#define ESR_ELx_EC_PAC		(0x09)	/* EL2 and above */
/* Unallocated EC: 0x0A - 0x0B */
#define ESR_ELx_EC_CP14_64	(0x0C)
/* Unallocated EC: 0x0d */
#define ESR_ELx_EC_ILL		(0x0E)
/* Unallocated EC: 0x0F - 0x10 */
#define ESR_ELx_EC_SVC32	(0x11)
#define ESR_ELx_EC_HVC32	(0x12)	/* EL2 only */
#define ESR_ELx_EC_SMC32	(0x13)	/* EL2 and above */
/* Unallocated EC: 0x14 */
#define ESR_ELx_EC_SVC64	(0x15)
#define ESR_ELx_EC_HVC64	(0x16)	/* EL2 and above */
#define ESR_ELx_EC_SMC64	(0x17)	/* EL2 and above */
#define ESR_ELx_EC_SYS64	(0x18)
#define ESR_ELx_EC_SVE		(0x19)
/* Unallocated EC: 0x1A - 0x1E */
#define ESR_ELx_EC_IMP_DEF	(0x1f)	/* EL3 only */
#define ESR_ELx_EC_IABT_LOW	(0x20)
#define ESR_ELx_EC_IABT_CUR	(0x21)
#define ESR_ELx_EC_PC_ALIGN	(0x22)
/* Unallocated EC: 0x23 */
#define ESR_ELx_EC_DABT_LOW	(0x24)
#define ESR_ELx_EC_DABT_CUR	(0x25)
#define ESR_ELx_EC_SP_ALIGN	(0x26)
/* Unallocated EC: 0x27 */
#define ESR_ELx_EC_FP_EXC32	(0x28)
/* Unallocated EC: 0x29 - 0x2B */
#define ESR_ELx_EC_FP_EXC64	(0x2C)
/* Unallocated EC: 0x2D - 0x2E */
#define ESR_ELx_EC_SERROR	(0x2F)
#define ESR_ELx_EC_BREAKPT_LOW	(0x30)
#define ESR_ELx_EC_BREAKPT_CUR	(0x31)
#define ESR_ELx_EC_SOFTSTP_LOW	(0x32)
#define ESR_ELx_EC_SOFTSTP_CUR	(0x33)
#define ESR_ELx_EC_WATCHPT_LOW	(0x34)
#define ESR_ELx_EC_WATCHPT_CUR	(0x35)
/* Unallocated EC: 0x36 - 0x37 */
#define ESR_ELx_EC_BKPT32	(0x38)
/* Unallocated EC: 0x39 */
#define ESR_ELx_EC_VECTOR32	(0x3A)	/* EL2 only */
/* Unallocted EC: 0x3B */
#define ESR_ELx_EC_BRK64	(0x3C)
/* Unallocated EC: 0x3D - 0x3F */
#define ESR_ELx_EC_MAX		(0x3F)

#define ESR_ELx_EC_SHIFT	(26)
#define ESR_ELx_EC_MASK		(UL(0x3F) << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)		(((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)

#define ESR_ELx_IL_SHIFT	(25)
#define ESR_ELx_IL		(UL(1) << ESR_ELx_IL_SHIFT)
#define ESR_ELx_ISS_MASK	(ESR_ELx_IL - 1)

/* ISS field definitions shared by different classes */
#define ESR_ELx_WNR_SHIFT	(6)
#define ESR_ELx_WNR		(UL(1) << ESR_ELx_WNR_SHIFT)

/* Asynchronous Error Type */
#define ESR_ELx_IDS_SHIFT	(24)
#define ESR_ELx_IDS		(UL(1) << ESR_ELx_IDS_SHIFT)
#define ESR_ELx_AET_SHIFT	(10)
#define ESR_ELx_AET		(UL(0x7) << ESR_ELx_AET_SHIFT)

#define ESR_ELx_AET_UC		(UL(0) << ESR_ELx_AET_SHIFT)
#define ESR_ELx_AET_UEU		(UL(1) << ESR_ELx_AET_SHIFT)
#define ESR_ELx_AET_UEO		(UL(2) << ESR_ELx_AET_SHIFT)
#define ESR_ELx_AET_UER		(UL(3) << ESR_ELx_AET_SHIFT)
#define ESR_ELx_AET_CE		(UL(6) << ESR_ELx_AET_SHIFT)

/* Shared ISS field definitions for Data/Instruction aborts */
#define ESR_ELx_SET_SHIFT	(11)
#define ESR_ELx_SET_MASK	(UL(3) << ESR_ELx_SET_SHIFT)
#define ESR_ELx_FnV_SHIFT	(10)
#define ESR_ELx_FnV		(UL(1) << ESR_ELx_FnV_SHIFT)
#define ESR_ELx_EA_SHIFT	(9)
#define ESR_ELx_EA		(UL(1) << ESR_ELx_EA_SHIFT)
#define ESR_ELx_S1PTW_SHIFT	(7)
#define ESR_ELx_S1PTW		(UL(1) << ESR_ELx_S1PTW_SHIFT)

/* Shared ISS fault status code(IFSC/DFSC) for Data/Instruction aborts */
#define ESR_ELx_FSC		(0x3F)
#define ESR_ELx_FSC_TYPE	(0x3C)
#define ESR_ELx_FSC_EXTABT	(0x10)
#define ESR_ELx_FSC_SERROR	(0x11)
#define ESR_ELx_FSC_ACCESS	(0x08)
#define ESR_ELx_FSC_FAULT	(0x04)
#define ESR_ELx_FSC_PERM	(0x0C)

/* ISS field definitions for Data Aborts */
#define ESR_ELx_ISV_SHIFT	(24)
#define ESR_ELx_ISV		(UL(1) << ESR_ELx_ISV_SHIFT)
#define ESR_ELx_SAS_SHIFT	(22)
#define ESR_ELx_SAS		(UL(3) << ESR_ELx_SAS_SHIFT)
#define ESR_ELx_SSE_SHIFT	(21)
#define ESR_ELx_SSE		(UL(1) << ESR_ELx_SSE_SHIFT)
#define ESR_ELx_SRT_SHIFT	(16)
#define ESR_ELx_SRT_MASK	(UL(0x1F) << ESR_ELx_SRT_SHIFT)
#define ESR_ELx_SF_SHIFT	(15)
#define ESR_ELx_SF 		(UL(1) << ESR_ELx_SF_SHIFT)
#define ESR_ELx_AR_SHIFT	(14)
#define ESR_ELx_AR 		(UL(1) << ESR_ELx_AR_SHIFT)
#define ESR_ELx_CM_SHIFT	(8)
#define ESR_ELx_CM 		(UL(1) << ESR_ELx_CM_SHIFT)

/* ISS field definitions for exceptions taken in to Hyp */
#define ESR_ELx_CV		(UL(1) << 24)
#define ESR_ELx_COND_SHIFT	(20)
#define ESR_ELx_COND_MASK	(UL(0xF) << ESR_ELx_COND_SHIFT)
#define ESR_ELx_WFx_ISS_TI	(UL(1) << 0)
#define ESR_ELx_WFx_ISS_WFI	(UL(0) << 0)
#define ESR_ELx_WFx_ISS_WFE	(UL(1) << 0)
#define ESR_ELx_xVC_IMM_MASK	((1UL << 16) - 1)

/* ISS field definitions for system error */
#define ESR_ELx_SERR_MASK	(0x1)
#define ESR_ELx_SERR_NMI	(0x1)

// LOAD_KERNEL_ADDRESS loads a kernel address.
#define LOAD_KERNEL_ADDRESS(from, to) \
	MOVD from, to; \
	ORR $0xffff000000000000, to, to;

// LOAD_KERNEL_STACK loads the kernel temporary stack.
#define LOAD_KERNEL_STACK(from) \
	LOAD_KERNEL_ADDRESS(CPU_SELF(from), RSV_REG); \
	MOVD $CPU_STACK_TOP(RSV_REG), RSV_REG; \
	MOVD RSV_REG, RSP; \
	WORD $0xd538d092;   //MRS   TPIDR_EL1, R18

// SWITCH_TO_APP_PAGETABLE sets a new pagetable for a container application.
#define SWITCH_TO_APP_PAGETABLE() \
	MOVD CPU_APP_ASID(RSV_REG), RSV_REG_APP; \
	MOVD CPU_TTBR0_APP(RSV_REG), RSV_REG; \
	BFI $48, RSV_REG_APP, $16, RSV_REG; \
	MSR RSV_REG, TTBR0_EL1; \
	ISB $15;

// SWITCH_TO_KVM_PAGETABLE sets the kvm pagetable.
#define SWITCH_TO_KVM_PAGETABLE() \
	MOVD CPU_TTBR0_KVM(RSV_REG), RSV_REG; \
	MOVD $1, RSV_REG_APP; \
	BFI $48, RSV_REG_APP, $16, RSV_REG; \
	MSR RSV_REG, TTBR0_EL1; \
	ISB $15;

// FPSIMDDisableTrap disables the trap for accessing fpsimd.
TEXT ·FPSIMDDisableTrap(SB),NOSPLIT,$0
	MOVD $FPEN_ENABLE, R0
	MSR R0, CPACR_EL1
	ISB $15
	RET

// FPSIMDEnableTrap enables the trap for accessing fpsimd.
TEXT ·FPSIMDEnableTrap(SB),NOSPLIT,$0
	MSR $0, CPACR_EL1
	ISB $15
	RET

// FPSIMD_DISABLE_TRAP disables the trap for accessing fpsimd.
#define FPSIMD_DISABLE_TRAP(reg) \
	MOVD $FPEN_ENABLE, reg; \
	MSR reg, CPACR_EL1; \
	ISB $15;

// FPSIMD_ENABLE_TRAP enables the trap for accessing fpsimd.
#define FPSIMD_ENABLE_TRAP(reg) \
	MSR $0, CPACR_EL1; \
	ISB $15;

// KERNEL_ENTRY_FROM_EL0 is the entry code of the vcpu from el0 to el1.
#define KERNEL_ENTRY_FROM_EL0 \
	SUB $16, RSP, RSP; \		// step1, save r18, r19 into kernel temporary stack.
	STP (RSV_REG, RSV_REG_APP), 16*0(RSP); \
	WORD $0xd538d092; \    // MRS   TPIDR_EL1, R18
	MOVD CPU_APP_ADDR(RSV_REG), RSV_REG_APP; \ // step2, load app context pointer.
	REGISTERS_SAVE(RSV_REG_APP, 0); \          // step3, save app context.
	MOVD RSV_REG_APP, R20; \
	LDP 16*0(RSP), (RSV_REG, RSV_REG_APP); \
	ADD $16, RSP, RSP; \
	STP (RSV_REG, RSV_REG_APP), PTRACE_R18(R20); \
	MRS TPIDR_EL0, R3; \
	MOVD R3, PTRACE_TLS(R20); \
	WORD $0xd5384003; \      //  MRS SPSR_EL1, R3
	MOVD R3, PTRACE_PSTATE(R20); \
	MRS ELR_EL1, R3; \
	MOVD R3, PTRACE_PC(R20); \
	WORD $0xd5384103; \      //  MRS SP_EL0, R3
	MOVD R3, PTRACE_SP(R20);

// KERNEL_ENTRY_FROM_EL1 is the entry code of the vcpu from el1 to el1.
#define KERNEL_ENTRY_FROM_EL1 \
	WORD $0xd538d092; \   //MRS   TPIDR_EL1, R18
	REGISTERS_SAVE(RSV_REG, CPU_REGISTERS); \	// Save sentry context.
	MOVD RSV_REG_APP, CPU_REGISTERS+PTRACE_R19(RSV_REG); \
	MRS TPIDR_EL0, R4; \
	MOVD R4, CPU_REGISTERS+PTRACE_TLS(RSV_REG); \
	WORD $0xd5384004; \    //    MRS SPSR_EL1, R4
	MOVD R4, CPU_REGISTERS+PTRACE_PSTATE(RSV_REG); \
	MRS ELR_EL1, R4; \
	MOVD R4, CPU_REGISTERS+PTRACE_PC(RSV_REG); \
	MOVD RSP, R4; \
	MOVD R4, CPU_REGISTERS+PTRACE_SP(RSV_REG); \
	LOAD_KERNEL_STACK(RSV_REG);  // Load the temporary stack.

// EXCEPTION_EL0 is a common el0 exception handler function.
#define EXCEPTION_EL0(vector) \
	WORD $0xd538d092; \	//MRS   TPIDR_EL1, R18
	WORD $0xd538601a; \	//MRS   FAR_EL1, R26
	MOVD R26, CPU_FAULT_ADDR(RSV_REG); \
	MOVD $1, R3; \
	MOVD R3, CPU_ERROR_TYPE(RSV_REG); \	// Set error type to user.
	MOVD $vector, R3; \
	MOVD R3, CPU_VECTOR_CODE(RSV_REG); \
	MRS ESR_EL1, R3; \
	MOVD R3, CPU_ERROR_CODE(RSV_REG); \
	B ·kernelExitToEl1(SB);

// EXCEPTION_EL1 is a common el1 exception handler function.
#define EXCEPTION_EL1(vector) \
	MOVD $vector, R3; \
	MOVD R3, 8(RSP); \
	B ·HaltEl1ExceptionAndResume(SB);

// storeEl0Fpstate writes the address of application's fpstate.
TEXT ·storeEl0Fpstate(SB),NOSPLIT,$0-8
	MOVD value+0(FP), R1
	ORR $0xffff000000000000, R1, R1
	MRS  TPIDR_EL1, RSV_REG
	MOVD R1, CPU_FPSTATE_EL0(RSV_REG)
	RET

// storeAppASID writes the application's asid value.
TEXT ·storeAppASID(SB),NOSPLIT,$0-8
	MOVD asid+0(FP), R1
	MRS  TPIDR_EL1, RSV_REG
	MOVD R1, CPU_APP_ASID(RSV_REG)
	RET

// Halt halts execution.
TEXT ·Halt(SB),NOSPLIT,$0
	// Disable fpsimd.
	WORD $0xd5381041 // MRS CPACR_EL1, R1
	MOVD R1, CPU_LAZY_VFP(RSV_REG)
	DSB $15

	FPSIMD_ENABLE_TRAP(RSV_REG)

	// Trigger MMIO_EXIT/_KVM_HYPERCALL_VMEXIT.
	//
	// To keep it simple, I used the address of exception table as the
	// MMIO base address, so that I can trigger a MMIO-EXIT by forcibly writing
	// a read-only space.
	// Also, the length is engough to match a sufficient number of hypercall ID.
	// Then, in host user space, I can calculate this address to find out
	// which hypercall.
	MRS VBAR_EL1, R9
	MOVD R0, 0x0(R9)

	RET

// HaltAndResume halts execution and point the pointer to the resume function.
TEXT ·HaltAndResume(SB),NOSPLIT,$0
	BL ·Halt(SB)
	B ·kernelExitToEl1(SB) // Resume.

// HaltEl1SvcAndResume calls Hooks.KernelSyscall and resume.
TEXT ·HaltEl1SvcAndResume(SB),NOSPLIT,$0
	WORD $0xd538d092            // MRS TPIDR_EL1, R18
	MOVD CPU_SELF(RSV_REG), R3  // Load vCPU.
	MOVD R3, 8(RSP)             // First argument (vCPU).
	CALL ·kernelSyscall(SB)     // Call the trampoline.
	B ·kernelExitToEl1(SB)      // Resume.

// HaltEl1ExceptionAndResume calls Hooks.KernelException and resume.
TEXT ·HaltEl1ExceptionAndResume(SB),NOSPLIT,$0-8
	WORD $0xd538d092            // MRS TPIDR_EL1, R18
	MOVD CPU_SELF(RSV_REG), R3  // Load vCPU.
	MOVD R3, 8(RSP)             // First argument (vCPU).
	MOVD vector+0(FP), R3
	MOVD R3, 16(RSP)            // Second argument (vector).
	CALL ·kernelException(SB)   // Call the trampoline.
	B ·kernelExitToEl1(SB)      // Resume.

// Shutdown stops the guest.
TEXT ·Shutdown(SB),NOSPLIT,$0
	// PSCI EVENT.
	MOVD $0x84000009, R0
	HVC $0

// See kernel.go.
TEXT ·Current(SB),NOSPLIT,$0-8
	MOVD CPU_SELF(RSV_REG), R8
	MOVD R8, ret+0(FP)
	RET

#define STACK_FRAME_SIZE 32

// kernelExitToEl0 is the entrypoint for application in guest_el0.
// Prepare the vcpu environment for container application.
TEXT ·kernelExitToEl0(SB),NOSPLIT,$0
	// Step1, save sentry context into memory.
	MRS TPIDR_EL1, RSV_REG
	REGISTERS_SAVE(RSV_REG, CPU_REGISTERS)
	MOVD RSV_REG_APP, CPU_REGISTERS+PTRACE_R19(RSV_REG)
	MRS TPIDR_EL0, R3
	MOVD R3, CPU_REGISTERS+PTRACE_TLS(RSV_REG)

	WORD $0xd5384003    //    MRS SPSR_EL1, R3
	MOVD R3, CPU_REGISTERS+PTRACE_PSTATE(RSV_REG)
	MOVD R30, CPU_REGISTERS+PTRACE_PC(RSV_REG)
	MOVD RSP, R3
	MOVD R3, CPU_REGISTERS+PTRACE_SP(RSV_REG)

	MOVD CPU_REGISTERS+PTRACE_R3(RSV_REG), R3

	// Step2, switch to temporary stack.
	LOAD_KERNEL_STACK(RSV_REG)

	// Step3, load app context pointer.
	MOVD CPU_APP_ADDR(RSV_REG), RSV_REG_APP

	// Step4, prepare the environment for container application.
	// set sp_el0.
	MOVD PTRACE_SP(RSV_REG_APP), R1
	WORD $0xd5184101        //MSR R1, SP_EL0
	// set pc.
	MOVD PTRACE_PC(RSV_REG_APP), R1
	MSR R1, ELR_EL1
	// set pstate.
	MOVD PTRACE_PSTATE(RSV_REG_APP), R1
	WORD $0xd5184001  //MSR R1, SPSR_EL1

	// need use kernel space address to excute below code, since
	// after SWITCH_TO_APP_PAGETABLE the ASID is changed to app's
	// ASID.
	WORD $0x10000061		// ADR R1, do_exit_to_el0
	ORR $0xffff000000000000, R1, R1
	JMP (R1)

do_exit_to_el0:
	// RSV_REG & RSV_REG_APP will be loaded at the end.
	REGISTERS_LOAD(RSV_REG_APP, 0)
	MOVD PTRACE_TLS(RSV_REG_APP), RSV_REG
	MSR RSV_REG, TPIDR_EL0

	// switch to user pagetable.
	LDP PTRACE_R18(RSV_REG_APP), (RSV_REG, RSV_REG_APP)

	SUB $STACK_FRAME_SIZE, RSP, RSP
	STP (RSV_REG, RSV_REG_APP), 16*0(RSP)
	STP (R0, R1), 16*1(RSP)

	WORD $0xd538d092    //MRS   TPIDR_EL1, R18

	SWITCH_TO_APP_PAGETABLE()

	LDP 16*1(RSP), (R0, R1)
	LDP 16*0(RSP), (RSV_REG, RSV_REG_APP)
	ADD $STACK_FRAME_SIZE, RSP, RSP

	ERET()

// kernelExitToEl1 is the entrypoint for sentry in guest_el1.
// Prepare the vcpu environment for sentry.
TEXT ·kernelExitToEl1(SB),NOSPLIT,$0
	WORD $0xd538d092     //MRS   TPIDR_EL1, R18
	MOVD CPU_REGISTERS+PTRACE_PSTATE(RSV_REG), R1
	WORD $0xd5184001  //MSR R1, SPSR_EL1

	MOVD CPU_REGISTERS+PTRACE_PC(RSV_REG), R1
	MSR R1, ELR_EL1

	// restore sentry's tls.
	MOVD CPU_REGISTERS+PTRACE_TLS(RSV_REG), R1
	MSR R1, TPIDR_EL0

	MOVD CPU_REGISTERS+PTRACE_SP(RSV_REG), R1
	MOVD R1, RSP

	REGISTERS_LOAD(RSV_REG, CPU_REGISTERS)
	SWITCH_TO_KVM_PAGETABLE()
	MRS TPIDR_EL1, RSV_REG

	MOVD CPU_REGISTERS+PTRACE_R19(RSV_REG), RSV_REG_APP

	ERET()

// start is the CPU entrypoint.
TEXT ·start(SB),NOSPLIT,$0
	// Init.
	WORD $0xd508871f    // __tlbi(vmalle1)
	DSB $7          // dsb(nsh)

	MOVD $1<<12, R1         // Reset mdscr_el1 and disable
	MSR R1, MDSCR_EL1       // access to the DCC from EL0
	ISB $15

	MRS TTBR1_EL1, R1
	MSR R1, TTBR0_EL1
	ISB $15

	MOVD $CNTKCTL_EL1_DEFAULT, R1
	MSR R1, CNTKCTL_EL1

	MOVD R8, RSV_REG
	ORR $0xffff000000000000, RSV_REG, RSV_REG
	WORD $0xd518d092        //MSR R18, TPIDR_EL1

	// Enable trap for accessing fpsimd.
	MSR $0, CPACR_EL1

	// Init.
	MOVD $SCTLR_EL1_DEFAULT, R1 // re-enable the mmu.
	MSR R1, SCTLR_EL1
	ISB $15
	WORD $0xd508751f // ic iallu

	DSB $7          // dsb(nsh)
	ISB $15

	B ·kernelExitToEl1(SB)

// func AddrOfStart() uintptr
TEXT ·AddrOfStart(SB), $0-8
	MOVD	$·start(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// El1_sync_invalid is the handler for an invalid EL1_sync.
TEXT ·El1_sync_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El1_irq_invalid is the handler for an invalid El1_irq.
TEXT ·El1_irq_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El1_fiq_invalid is the handler for an invalid El1_fiq.
TEXT ·El1_fiq_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El1_error_invalid is the handler for an invalid El1_error.
TEXT ·El1_error_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El1_sync is the handler for El1_sync.
TEXT ·El1_sync(SB),NOSPLIT,$0
	KERNEL_ENTRY_FROM_EL1
	MRS ESR_EL1, R25                  // read the syndrome register
	LSR  $ESR_ELx_EC_SHIFT, R25, R24  // exception class
	CMP $ESR_ELx_EC_DABT_CUR, R24
	BEQ el1_da                        // data abort in EL1
	CMP $ESR_ELx_EC_IABT_CUR, R24
	BEQ el1_ia                        // instruction abort in EL1
	CMP $ESR_ELx_EC_FP_ASIMD, R24
	BEQ el1_fpsimd_acc                // FP/ASIMD access
	CMP $ESR_ELx_EC_SVE, R24
	BEQ el1_sve_acc                   // SVE access
	CMP $ESR_ELx_EC_SP_ALIGN, R24
	BEQ el1_sp_pc                     // stack alignment exception
	CMP $ESR_ELx_EC_PC_ALIGN, R24
	BEQ el1_sp_pc                     // pc alignment exception
	CMP $ESR_ELx_EC_UNKNOWN, R24
	BEQ el1_undef                     // unknown exception in EL1
	CMP $ESR_ELx_EC_SVC64, R24
	BEQ el1_svc                       // SVC in 64-bit state
	CMP $ESR_ELx_EC_BREAKPT_CUR, R24
	BEQ el1_dbg                       // debug exception in EL1
	B el1_invalid

el1_da:
	EXCEPTION_EL1(El1SyncDa)
el1_ia:
	EXCEPTION_EL1(El1SyncIa)
el1_sp_pc:
	EXCEPTION_EL1(El1SyncSpPc)
el1_undef:
	EXCEPTION_EL1(El1SyncUndef)
el1_svc:
	B ·HaltEl1SvcAndResume(SB)
el1_dbg:
	EXCEPTION_EL1(El1SyncDbg)
el1_fpsimd_acc:
el1_sve_acc:
	FPSIMD_DISABLE_TRAP(RSV_REG)

	// Restore context.
	MRS TPIDR_EL1, RSV_REG

	// Restore sp.
	MOVD CPU_REGISTERS+PTRACE_SP(RSV_REG), R1
	MOVD R1, RSP

	// Restore common registers.
	REGISTERS_LOAD(RSV_REG, CPU_REGISTERS)
	MOVD CPU_REGISTERS+PTRACE_R19(RSV_REG), RSV_REG_APP

	ERET()	// return to el1.

el1_invalid:
	EXCEPTION_EL1(El1SyncInv)

// El1_irq is the handler for El1_irq.
TEXT ·El1_irq(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El1_fiq is the handler for El1_fiq.
TEXT ·El1_fiq(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El1_error is the handler for El1_error.
TEXT ·El1_error(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// El0_sync is the handler for El0_sync.
TEXT ·El0_sync(SB),NOSPLIT,$0
	KERNEL_ENTRY_FROM_EL0
	MRS ESR_EL1, R25                  // read the syndrome register
	LSR  $ESR_ELx_EC_SHIFT, R25, R24  // exception class
	CMP $ESR_ELx_EC_SVC64, R24
	BEQ el0_svc                       // SVC in 64-bit state
	CMP $ESR_ELx_EC_DABT_LOW, R24
	BEQ el0_da                        // data abort in EL0
	CMP $ESR_ELx_EC_IABT_LOW, R24
	BEQ el0_ia                        // instruction abort in EL0
	CMP $ESR_ELx_EC_FP_ASIMD, R24
	BEQ el0_fpsimd_acc                // FP/ASIMD access
	CMP $ESR_ELx_EC_SVE, R24
	BEQ el0_sve_acc                   // SVE access
	CMP $ESR_ELx_EC_FP_EXC64, R24
	BEQ el0_fpsimd_exc                // FP/ASIMD exception
	CMP $ESR_ELx_EC_SP_ALIGN, R24
	BEQ el0_sp_pc                     // stack alignment exception
	CMP $ESR_ELx_EC_PC_ALIGN, R24
	BEQ el0_sp_pc                     // pc alignment exception
	CMP $ESR_ELx_EC_UNKNOWN, R24
	BEQ el0_undef                     // unknown exception in EL0
	CMP $ESR_ELx_EC_BREAKPT_LOW, R24
	BEQ el0_dbg                       // debug exception in EL0
	CMP $ESR_ELx_EC_SYS64, R24
	BEQ el0_sys                       // configurable trap
	CMP $ESR_ELx_EC_WFx, R24
	BEQ el0_wfx                       // WFX trap
	B   el0_invalid

el0_svc:
	WORD $0xd538d092     //MRS   TPIDR_EL1, R18

	MOVD $0, CPU_ERROR_CODE(RSV_REG) // Clear error code.

	MOVD $1, R3
	MOVD R3, CPU_ERROR_TYPE(RSV_REG) // Set error type to user.

	MOVD $Syscall, R3
	MOVD R3, CPU_VECTOR_CODE(RSV_REG)

	B ·kernelExitToEl1(SB)

el0_da:
el0_ia:
	EXCEPTION_EL0(PageFault)
el0_fpsimd_acc:
el0_sve_acc:
	FPSIMD_DISABLE_TRAP(RSV_REG)
	FPSTATE_EL0_LOAD()

	// Restore context.
	MRS TPIDR_EL1, RSV_REG
	MOVD CPU_APP_ADDR(RSV_REG), RSV_REG_APP

	// Restore R0-R30
	REGISTERS_LOAD(RSV_REG_APP, 0)
	MOVD PTRACE_R18(RSV_REG_APP), RSV_REG
	MOVD PTRACE_R19(RSV_REG_APP), RSV_REG_APP

	ERET()  // return to el0.
el0_fpsimd_exc:
	EXCEPTION_EL0(El0SyncFpsimdExc)
el0_sp_pc:
	EXCEPTION_EL0(El0SyncSpPc)
el0_undef:
	EXCEPTION_EL0(El0SyncUndef)
el0_dbg:
	EXCEPTION_EL0(El0SyncDbg)
el0_sys:
	EXCEPTION_EL0(El0SyncSys)
el0_wfx:
	EXCEPTION_EL0(El0SyncWfx)
el0_invalid:
	EXCEPTION_EL0(El0SyncInv)

TEXT ·El0_irq(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_fiq(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_error(SB),NOSPLIT,$0
	KERNEL_ENTRY_FROM_EL0
	WORD $0xd5385219        // MRS ESR_EL1, R25
	AND $ESR_ELx_SERR_MASK, R25, R24
	CMP $ESR_ELx_SERR_NMI, R24
	BEQ el0_nmi
	B el0_bounce

el0_nmi:
	EXCEPTION_EL0(El0ErrNMI)
el0_bounce:
	EXCEPTION_EL0(VirtualizationException)

TEXT ·El0_sync_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_irq_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_fiq_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_error_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// vectors implements exception vector table.
// The start address of exception vector table should be 11-bits aligned.
// For detail, please refer to arm developer document:
// https://developer.arm.com/documentation/100933/0100/AArch64-exception-vector-table
// Also can refer to the code in linux kernel: arch/arm64/kernel/entry.S
TEXT ·vectors(SB),NOSPLIT,$0
	PCALIGN $2048
	B ·El1_sync_invalid(SB)
	PCALIGN $128
	B ·El1_irq_invalid(SB)
	PCALIGN $128
	B ·El1_fiq_invalid(SB)
	PCALIGN $128
	B ·El1_error_invalid(SB)

	PCALIGN $128
	B ·El1_sync(SB)
	PCALIGN $128
	B ·El1_irq(SB)
	PCALIGN $128
	B ·El1_fiq(SB)
	PCALIGN $128
	B ·El1_error(SB)

	PCALIGN $128
	B ·El0_sync(SB)
	PCALIGN $128
	B ·El0_irq(SB)
	PCALIGN $128
	B ·El0_fiq(SB)
	PCALIGN $128
	B ·El0_error(SB)

	PCALIGN $128
	B ·El0_sync_invalid(SB)
	PCALIGN $128
	B ·El0_irq_invalid(SB)
	PCALIGN $128
	B ·El0_fiq_invalid(SB)
	PCALIGN $128
	B ·El0_error_invalid(SB)

// func AddrOfVectors() uintptr
TEXT ·AddrOfVectors(SB), $0-8
       MOVD    $·vectors(SB), R0
       MOVD    R0, ret+0(FP)
       RET
