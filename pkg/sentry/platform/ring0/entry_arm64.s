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

// NB: Offsets are programatically generated (see BUILD).
//
// This file is concatenated with the definitions.

// Saves a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//

// ERET returns using the ELR and SPSR for the current exception level.
#define ERET() \
  WORD $0xd69f03e0

// RSV_REG is a register that holds el1 information temporarily.
#define RSV_REG 	R18_PLATFORM

// RSV_REG_APP is a register that holds el0 information temporarily.
#define RSV_REG_APP 	R9

#define FPEN_NOTRAP 	0x3
#define FPEN_SHIFT 	20

#define FPEN_ENABLE (FPEN_NOTRAP << FPEN_SHIFT)

// sctlr_el1: system control register el1.
#define SCTLR_M         1 << 0
#define SCTLR_C         1 << 2
#define SCTLR_I         1 << 12
#define SCTLR_UCT       1 << 15

#define SCTLR_EL1_DEFAULT       (SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_UCT)

// cntkctl_el1: counter-timer kernel control register el1.
#define CNTKCTL_EL0PCTEN 	1 << 0
#define CNTKCTL_EL0VCTEN 	1 << 1

#define CNTKCTL_EL1_DEFAULT 	(CNTKCTL_EL0PCTEN | CNTKCTL_EL0VCTEN)

// Saves a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
// The following registers are not saved: R9, R18.
#define REGISTERS_SAVE(reg, offset) \
  MOVD R0, offset+PTRACE_R0(reg); \
  MOVD R1, offset+PTRACE_R1(reg); \
  MOVD R2, offset+PTRACE_R2(reg); \
  MOVD R3, offset+PTRACE_R3(reg); \
  MOVD R4, offset+PTRACE_R4(reg); \
  MOVD R5, offset+PTRACE_R5(reg); \
  MOVD R6, offset+PTRACE_R6(reg); \
  MOVD R7, offset+PTRACE_R7(reg); \
  MOVD R8, offset+PTRACE_R8(reg); \
  MOVD R10, offset+PTRACE_R10(reg); \
  MOVD R11, offset+PTRACE_R11(reg); \
  MOVD R12, offset+PTRACE_R12(reg); \
  MOVD R13, offset+PTRACE_R13(reg); \
  MOVD R14, offset+PTRACE_R14(reg); \
  MOVD R15, offset+PTRACE_R15(reg); \
  MOVD R16, offset+PTRACE_R16(reg); \
  MOVD R17, offset+PTRACE_R17(reg); \
  MOVD R19, offset+PTRACE_R19(reg); \
  MOVD R20, offset+PTRACE_R20(reg); \
  MOVD R21, offset+PTRACE_R21(reg); \
  MOVD R22, offset+PTRACE_R22(reg); \
  MOVD R23, offset+PTRACE_R23(reg); \
  MOVD R24, offset+PTRACE_R24(reg); \
  MOVD R25, offset+PTRACE_R25(reg); \
  MOVD R26, offset+PTRACE_R26(reg); \
  MOVD R27, offset+PTRACE_R27(reg); \
  MOVD g,   offset+PTRACE_R28(reg); \
  MOVD R29, offset+PTRACE_R29(reg); \
  MOVD R30, offset+PTRACE_R30(reg);

// Loads a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
// The following registers are not loaded: R9, R18.
#define REGISTERS_LOAD(reg, offset) \
  MOVD offset+PTRACE_R0(reg), R0; \
  MOVD offset+PTRACE_R1(reg), R1; \
  MOVD offset+PTRACE_R2(reg), R2; \
  MOVD offset+PTRACE_R3(reg), R3; \
  MOVD offset+PTRACE_R4(reg), R4; \
  MOVD offset+PTRACE_R5(reg), R5; \
  MOVD offset+PTRACE_R6(reg), R6; \
  MOVD offset+PTRACE_R7(reg), R7; \
  MOVD offset+PTRACE_R8(reg), R8; \
  MOVD offset+PTRACE_R10(reg), R10; \
  MOVD offset+PTRACE_R11(reg), R11; \
  MOVD offset+PTRACE_R12(reg), R12; \
  MOVD offset+PTRACE_R13(reg), R13; \
  MOVD offset+PTRACE_R14(reg), R14; \
  MOVD offset+PTRACE_R15(reg), R15; \
  MOVD offset+PTRACE_R16(reg), R16; \
  MOVD offset+PTRACE_R17(reg), R17; \
  MOVD offset+PTRACE_R19(reg), R19; \
  MOVD offset+PTRACE_R20(reg), R20; \
  MOVD offset+PTRACE_R21(reg), R21; \
  MOVD offset+PTRACE_R22(reg), R22; \
  MOVD offset+PTRACE_R23(reg), R23; \
  MOVD offset+PTRACE_R24(reg), R24; \
  MOVD offset+PTRACE_R25(reg), R25; \
  MOVD offset+PTRACE_R26(reg), R26; \
  MOVD offset+PTRACE_R27(reg), R27; \
  MOVD offset+PTRACE_R28(reg), g; \
  MOVD offset+PTRACE_R29(reg), R29; \
  MOVD offset+PTRACE_R30(reg), R30;

// NOP-s
#define nop31Instructions() \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f; \
        WORD $0xd503201f;

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

// LOAD_KERNEL_ADDRESS loads a kernel address.
#define LOAD_KERNEL_ADDRESS(from, to) \
	MOVD from, to; \
	ORR $0xffff000000000000, to, to;

// LOAD_KERNEL_STACK loads the kernel temporary stack.
#define LOAD_KERNEL_STACK(from) \
	LOAD_KERNEL_ADDRESS(CPU_SELF(from), RSV_REG); \
	MOVD $CPU_STACK_TOP(RSV_REG), RSV_REG; \
	MOVD RSV_REG, RSP; \
	WORD $0xd538d092; \   //MRS   TPIDR_EL1, R18
	ISB $15; \
	DSB $15;

// SWITCH_TO_APP_PAGETABLE sets a new pagetable for a container application.
#define SWITCH_TO_APP_PAGETABLE(from) \
	MOVD CPU_TTBR0_APP(from), RSV_REG; \
	WORD $0xd5182012; \	//        MSR R18, TTBR0_EL1
	ISB $15; \
	DSB $15;

// SWITCH_TO_KVM_PAGETABLE sets the kvm pagetable.
#define SWITCH_TO_KVM_PAGETABLE(from) \
	MOVD CPU_TTBR0_KVM(from), RSV_REG; \
	WORD $0xd5182012; \	//        MSR R18, TTBR0_EL1
	ISB $15; \
	DSB $15;

#define VFP_ENABLE \
	MOVD $FPEN_ENABLE, R0; \
	WORD $0xd5181040; \ //MSR R0, CPACR_EL1
	ISB $15;

#define VFP_DISABLE \
	MOVD $0x0, R0; \
	WORD $0xd5181040; \ //MSR R0, CPACR_EL1
	ISB $15;

// KERNEL_ENTRY_FROM_EL0 is the entry code of the vcpu from el0 to el1.
#define KERNEL_ENTRY_FROM_EL0 \
	SUB $16, RSP, RSP; \		// step1, save r18, r9 into kernel temporary stack.
	STP (RSV_REG, RSV_REG_APP), 16*0(RSP); \
	WORD $0xd538d092; \    //MRS   TPIDR_EL1, R18, step2, switch user pagetable.
	SWITCH_TO_KVM_PAGETABLE(RSV_REG); \
	WORD $0xd538d092; \    //MRS   TPIDR_EL1, R18
	MOVD CPU_APP_ADDR(RSV_REG), RSV_REG_APP; \ // step3, load app context pointer.
	REGISTERS_SAVE(RSV_REG_APP, 0); \          // step4, save app context.
	MOVD RSV_REG_APP, R20; \
	LDP 16*0(RSP), (RSV_REG, RSV_REG_APP); \
	ADD $16, RSP, RSP; \
	MOVD RSV_REG, PTRACE_R18(R20); \
	MOVD RSV_REG_APP, PTRACE_R9(R20); \
	MOVD R20, RSV_REG_APP; \
	WORD $0xd5384003; \      //  MRS SPSR_EL1, R3
	MOVD R3, PTRACE_PSTATE(RSV_REG_APP); \
	MRS ELR_EL1, R3; \
	MOVD R3, PTRACE_PC(RSV_REG_APP); \
	WORD $0xd5384103; \      //  MRS SP_EL0, R3
	MOVD R3, PTRACE_SP(RSV_REG_APP);

// KERNEL_ENTRY_FROM_EL1 is the entry code of the vcpu from el1 to el1.
#define KERNEL_ENTRY_FROM_EL1 \
	WORD $0xd538d092; \   //MRS   TPIDR_EL1, R18
	REGISTERS_SAVE(RSV_REG, CPU_REGISTERS); \	// Save sentry context.
	MOVD RSV_REG_APP, CPU_REGISTERS+PTRACE_R9(RSV_REG); \
	WORD $0xd5384004; \    //    MRS SPSR_EL1, R4
	MOVD R4, CPU_REGISTERS+PTRACE_PSTATE(RSV_REG); \
	MRS ELR_EL1, R4; \
	MOVD R4, CPU_REGISTERS+PTRACE_PC(RSV_REG); \
	MOVD RSP, R4; \
	MOVD R4, CPU_REGISTERS+PTRACE_SP(RSV_REG); \
	LOAD_KERNEL_STACK(RSV_REG);  // Load the temporary stack.

// Halt halts execution.
TEXT ·Halt(SB),NOSPLIT,$0
	// Clear bluepill.
	WORD $0xd538d092   //MRS   TPIDR_EL1, R18
	CMP RSV_REG, R9
	BNE mmio_exit
	MOVD $0, CPU_REGISTERS+PTRACE_R9(RSV_REG)

	// Flush dcache.
	WORD $0xd5087e52   // DC CISW
mmio_exit:
	// Disable fpsimd.
	WORD $0xd5381041 // MRS CPACR_EL1, R1
	MOVD R1, CPU_LAZY_VFP(RSV_REG)
	VFP_DISABLE

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

	// Flush dcahce.
	WORD $0xd5087e52  // DC CISW

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

#define STACK_FRAME_SIZE 16

// kernelExitToEl0 is the entrypoint for application in guest_el0.
// Prepare the vcpu environment for container application.
TEXT ·kernelExitToEl0(SB),NOSPLIT,$0
	// Step1, save sentry context into memory.
	MRS TPIDR_EL1, RSV_REG
	REGISTERS_SAVE(RSV_REG, CPU_REGISTERS)
	MOVD RSV_REG_APP, CPU_REGISTERS+PTRACE_R9(RSV_REG)

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

	// RSV_REG & RSV_REG_APP will be loaded at the end.
	REGISTERS_LOAD(RSV_REG_APP, 0)

	// switch to user pagetable.
	MOVD PTRACE_R18(RSV_REG_APP), RSV_REG
	MOVD PTRACE_R9(RSV_REG_APP), RSV_REG_APP

	SUB $STACK_FRAME_SIZE, RSP, RSP
	STP (RSV_REG, RSV_REG_APP), 16*0(RSP)

	WORD $0xd538d092    //MRS   TPIDR_EL1, R18

	SWITCH_TO_APP_PAGETABLE(RSV_REG)

	LDP 16*0(RSP), (RSV_REG, RSV_REG_APP)
	ADD $STACK_FRAME_SIZE, RSP, RSP

	ISB $15
	ERET()

// kernelExitToEl1 is the entrypoint for sentry in guest_el1.
// Prepare the vcpu environment for sentry.
TEXT ·kernelExitToEl1(SB),NOSPLIT,$0
	WORD $0xd538d092     //MRS   TPIDR_EL1, R18
	MOVD CPU_REGISTERS+PTRACE_PSTATE(RSV_REG), R1
	WORD $0xd5184001  //MSR R1, SPSR_EL1

	MOVD CPU_REGISTERS+PTRACE_PC(RSV_REG), R1
	MSR R1, ELR_EL1

	MOVD CPU_REGISTERS+PTRACE_SP(RSV_REG), R1
	MOVD R1, RSP

	REGISTERS_LOAD(RSV_REG, CPU_REGISTERS)
	MOVD CPU_REGISTERS+PTRACE_R9(RSV_REG), RSV_REG_APP

	ERET()

// Start is the CPU entrypoint.
TEXT ·Start(SB),NOSPLIT,$0
	// Flush dcache.
	WORD $0xd5087e52 // DC CISW
	// Init.
	MOVD $SCTLR_EL1_DEFAULT, R1
	MSR R1, SCTLR_EL1

	MOVD $CNTKCTL_EL1_DEFAULT, R1
	MSR R1, CNTKCTL_EL1

	MOVD R8, RSV_REG
	ORR $0xffff000000000000, RSV_REG, RSV_REG
	WORD $0xd518d092        //MSR R18, TPIDR_EL1

	B ·kernelExitToEl1(SB)

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
	WORD $0xd5385219        // MRS ESR_EL1, R25
	LSR  $ESR_ELx_EC_SHIFT, R25, R24
	CMP $ESR_ELx_EC_DABT_CUR, R24
	BEQ el1_da
	CMP $ESR_ELx_EC_IABT_CUR, R24
	BEQ el1_ia
	CMP $ESR_ELx_EC_SYS64, R24
	BEQ el1_undef
	CMP $ESR_ELx_EC_SP_ALIGN, R24
	BEQ el1_sp_pc
	CMP $ESR_ELx_EC_PC_ALIGN, R24
	BEQ el1_sp_pc
	CMP $ESR_ELx_EC_UNKNOWN, R24
	BEQ el1_undef
	CMP $ESR_ELx_EC_SVC64, R24
	BEQ el1_svc
	CMP $ESR_ELx_EC_BREAKPT_CUR, R24
	BGE el1_dbg
	CMP $ESR_ELx_EC_FP_ASIMD, R24
	BEQ el1_fpsimd_acc
	B el1_invalid

el1_da:
el1_ia:
	WORD $0xd538d092     //MRS   TPIDR_EL1, R18
	WORD $0xd538601a     //MRS   FAR_EL1, R26

	MOVD R26, CPU_FAULT_ADDR(RSV_REG)

	MOVD $0, CPU_ERROR_TYPE(RSV_REG)

	MOVD $PageFault, R3
	MOVD R3, CPU_VECTOR_CODE(RSV_REG)

	B ·HaltAndResume(SB)

el1_sp_pc:
	B ·Shutdown(SB)

el1_undef:
	B ·Shutdown(SB)

el1_svc:
	MOVD $0, CPU_ERROR_CODE(RSV_REG)
	MOVD $0, CPU_ERROR_TYPE(RSV_REG)
	B ·HaltEl1SvcAndResume(SB)

el1_dbg:
	B ·Shutdown(SB)

el1_fpsimd_acc:
	VFP_ENABLE
	B ·kernelExitToEl1(SB)  // Resume.

el1_invalid:
	B ·Shutdown(SB)

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
	WORD $0xd5385219	// MRS ESR_EL1, R25
	LSR  $ESR_ELx_EC_SHIFT, R25, R24
	CMP $ESR_ELx_EC_SVC64, R24
	BEQ el0_svc
	CMP $ESR_ELx_EC_DABT_LOW, R24
	BEQ el0_da
	CMP $ESR_ELx_EC_IABT_LOW, R24
	BEQ el0_ia
	CMP $ESR_ELx_EC_FP_ASIMD, R24
	BEQ el0_fpsimd_acc
	CMP $ESR_ELx_EC_SVE, R24
	BEQ el0_sve_acc
	CMP $ESR_ELx_EC_FP_EXC64, R24
	BEQ el0_fpsimd_exc
	CMP $ESR_ELx_EC_SP_ALIGN, R24
	BEQ el0_sp_pc
	CMP $ESR_ELx_EC_PC_ALIGN, R24
	BEQ el0_sp_pc
	CMP $ESR_ELx_EC_UNKNOWN, R24
	BEQ el0_undef
	CMP $ESR_ELx_EC_BREAKPT_LOW, R24
	BGE el0_dbg
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
	WORD $0xd538d092     //MRS   TPIDR_EL1, R18
	WORD $0xd538601a     //MRS   FAR_EL1, R26

	MOVD R26, CPU_FAULT_ADDR(RSV_REG)

	MOVD $1, R3
	MOVD R3, CPU_ERROR_TYPE(RSV_REG) // Set error type to user.

	MOVD $PageFault, R3
	MOVD R3, CPU_VECTOR_CODE(RSV_REG)

	MRS ESR_EL1, R3
	MOVD R3, CPU_ERROR_CODE(RSV_REG)

	B ·kernelExitToEl1(SB)

el0_fpsimd_acc:
	B ·Shutdown(SB)

el0_sve_acc:
	B ·Shutdown(SB)

el0_fpsimd_exc:
	B ·Shutdown(SB)

el0_sp_pc:
	B ·Shutdown(SB)

el0_undef:
	MOVD $El0Sync_undef, R3
	MOVD R3, CPU_VECTOR_CODE(RSV_REG)

	B ·kernelExitToEl1(SB)

el0_dbg:
	B ·Shutdown(SB)

el0_invalid:
	B ·Shutdown(SB)

TEXT ·El0_irq(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_fiq(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_error(SB),NOSPLIT,$0
	KERNEL_ENTRY_FROM_EL0
	WORD $0xd538d092     //MRS   TPIDR_EL1, R18
	WORD $0xd538601a     //MRS   FAR_EL1, R26

	MOVD R26, CPU_FAULT_ADDR(RSV_REG)

	MOVD $1, R3
	MOVD R3, CPU_ERROR_TYPE(RSV_REG) // Set error type to user.

	MOVD $VirtualizationException, R3
	MOVD R3, CPU_VECTOR_CODE(RSV_REG)

	B ·HaltAndResume(SB)

TEXT ·El0_sync_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_irq_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_fiq_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

TEXT ·El0_error_invalid(SB),NOSPLIT,$0
	B ·Shutdown(SB)

// Vectors implements exception vector table.
TEXT ·Vectors(SB),NOSPLIT,$0
	B ·El1_sync_invalid(SB)
	nop31Instructions()
	B ·El1_irq_invalid(SB)
	nop31Instructions()
	B ·El1_fiq_invalid(SB)
	nop31Instructions()
	B ·El1_error_invalid(SB)
	nop31Instructions()

	B ·El1_sync(SB)
	nop31Instructions()
	B ·El1_irq(SB)
	nop31Instructions()
	B ·El1_fiq(SB)
	nop31Instructions()
	B ·El1_error(SB)
	nop31Instructions()

	B ·El0_sync(SB)
	nop31Instructions()
	B ·El0_irq(SB)
	nop31Instructions()
	B ·El0_fiq(SB)
	nop31Instructions()
	B ·El0_error(SB)
	nop31Instructions()

	B ·El0_sync_invalid(SB)
	nop31Instructions()
	B ·El0_irq_invalid(SB)
	nop31Instructions()
	B ·El0_fiq_invalid(SB)
	nop31Instructions()
	B ·El0_error_invalid(SB)
	nop31Instructions()

	// The exception-vector-table is required to be 11-bits aligned.
	// Please see Linux source code as reference: arch/arm64/kernel/entry.s.
	// For gvisor, I defined it as 4K in length, filled the 2nd 2K part with NOPs.
	// So that, I can safely move the 1st 2K part into the address with 11-bits alignment.
	WORD $0xd503201f	//nop
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()

	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()

	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()

	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
	WORD $0xd503201f
	nop31Instructions()
