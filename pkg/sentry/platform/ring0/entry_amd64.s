// Copyright 2018 The gVisor Authors.
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
// The following registers are not saved: AX, SP, IP, FLAGS, all segments.
#define REGISTERS_SAVE(reg, offset) \
  MOVQ R15, offset+PTRACE_R15(reg); \
  MOVQ R14, offset+PTRACE_R14(reg); \
  MOVQ R13, offset+PTRACE_R13(reg); \
  MOVQ R12, offset+PTRACE_R12(reg); \
  MOVQ BP,  offset+PTRACE_RBP(reg); \
  MOVQ BX,  offset+PTRACE_RBX(reg); \
  MOVQ CX,  offset+PTRACE_RCX(reg); \
  MOVQ DX,  offset+PTRACE_RDX(reg); \
  MOVQ R11, offset+PTRACE_R11(reg); \
  MOVQ R10, offset+PTRACE_R10(reg); \
  MOVQ R9,  offset+PTRACE_R9(reg); \
  MOVQ R8,  offset+PTRACE_R8(reg); \
  MOVQ SI,  offset+PTRACE_RSI(reg); \
  MOVQ DI,  offset+PTRACE_RDI(reg);

// Loads a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
// The following registers are not loaded: AX, SP, IP, FLAGS, all segments.
#define REGISTERS_LOAD(reg, offset) \
  MOVQ offset+PTRACE_R15(reg), R15; \
  MOVQ offset+PTRACE_R14(reg), R14; \
  MOVQ offset+PTRACE_R13(reg), R13; \
  MOVQ offset+PTRACE_R12(reg), R12; \
  MOVQ offset+PTRACE_RBP(reg), BP; \
  MOVQ offset+PTRACE_RBX(reg), BX; \
  MOVQ offset+PTRACE_RCX(reg), CX; \
  MOVQ offset+PTRACE_RDX(reg), DX; \
  MOVQ offset+PTRACE_R11(reg), R11; \
  MOVQ offset+PTRACE_R10(reg), R10; \
  MOVQ offset+PTRACE_R9(reg),  R9; \
  MOVQ offset+PTRACE_R8(reg),  R8; \
  MOVQ offset+PTRACE_RSI(reg), SI; \
  MOVQ offset+PTRACE_RDI(reg), DI;

// SWAP_GS swaps the kernel GS (CPU).
#define SWAP_GS() \
	BYTE $0x0F; BYTE $0x01; BYTE $0xf8;

// IRET returns from an interrupt frame.
#define IRET() \
	BYTE $0x48; BYTE $0xcf;

// SYSRET64 executes the sysret instruction.
#define SYSRET64() \
	BYTE $0x48; BYTE $0x0f; BYTE $0x07;

// LOAD_KERNEL_ADDRESS loads a kernel address.
#define LOAD_KERNEL_ADDRESS(from, to) \
	MOVQ from, to; \
	ORQ ·KernelStartAddress(SB), to;

// LOAD_KERNEL_STACK loads the kernel stack.
#define LOAD_KERNEL_STACK(from) \
	LOAD_KERNEL_ADDRESS(CPU_SELF(from), SP); \
	LEAQ CPU_STACK_TOP(SP), SP;

// See kernel.go.
TEXT ·Halt(SB),NOSPLIT,$0
	HLT
	RET

// See entry_amd64.go.
TEXT ·swapgs(SB),NOSPLIT,$0
	SWAP_GS()
	RET

// See entry_amd64.go.
TEXT ·sysret(SB),NOSPLIT,$0-24
	// Save original state.
	LOAD_KERNEL_ADDRESS(cpu+0(FP), BX)
	LOAD_KERNEL_ADDRESS(regs+8(FP), AX)
	MOVQ SP, CPU_REGISTERS+PTRACE_RSP(BX)
	MOVQ BP, CPU_REGISTERS+PTRACE_RBP(BX)
	MOVQ AX, CPU_REGISTERS+PTRACE_RAX(BX)

	// Restore user register state.
	REGISTERS_LOAD(AX, 0)
	MOVQ PTRACE_RIP(AX), CX    // Needed for SYSRET.
	MOVQ PTRACE_FLAGS(AX), R11 // Needed for SYSRET.
	MOVQ PTRACE_RSP(AX), SP    // Restore the stack directly.
	MOVQ PTRACE_RAX(AX), AX    // Restore AX (scratch).
	SYSRET64()

// See entry_amd64.go.
TEXT ·iret(SB),NOSPLIT,$0-24
	// Save original state.
	LOAD_KERNEL_ADDRESS(cpu+0(FP), BX)
	LOAD_KERNEL_ADDRESS(regs+8(FP), AX)
	MOVQ SP, CPU_REGISTERS+PTRACE_RSP(BX)
	MOVQ BP, CPU_REGISTERS+PTRACE_RBP(BX)
	MOVQ AX, CPU_REGISTERS+PTRACE_RAX(BX)

	// Build an IRET frame & restore state.
	LOAD_KERNEL_STACK(BX)
	MOVQ PTRACE_SS(AX), BX;    PUSHQ BX
	MOVQ PTRACE_RSP(AX), CX;   PUSHQ CX
	MOVQ PTRACE_FLAGS(AX), DX; PUSHQ DX
	MOVQ PTRACE_CS(AX), DI;    PUSHQ DI
	MOVQ PTRACE_RIP(AX), SI;   PUSHQ SI
	REGISTERS_LOAD(AX, 0)   // Restore most registers.
	MOVQ PTRACE_RAX(AX), AX // Restore AX (scratch).
	IRET()

// See entry_amd64.go.
TEXT ·resume(SB),NOSPLIT,$0
	// See iret, above.
	MOVQ CPU_REGISTERS+PTRACE_SS(GS), BX;    PUSHQ BX
	MOVQ CPU_REGISTERS+PTRACE_RSP(GS), CX;   PUSHQ CX
	MOVQ CPU_REGISTERS+PTRACE_FLAGS(GS), DX; PUSHQ DX
	MOVQ CPU_REGISTERS+PTRACE_CS(GS), DI;    PUSHQ DI
	MOVQ CPU_REGISTERS+PTRACE_RIP(GS), SI;   PUSHQ SI
	REGISTERS_LOAD(GS, CPU_REGISTERS)
	MOVQ CPU_REGISTERS+PTRACE_RAX(GS), AX
	IRET()

// See entry_amd64.go.
TEXT ·Start(SB),NOSPLIT,$0
	LOAD_KERNEL_STACK(AX) // Set the stack.
	PUSHQ $0x0            // Previous frame pointer.
	MOVQ SP, BP           // Set frame pointer.
	PUSHQ AX              // First argument (CPU).
	CALL ·start(SB)       // Call Go hook.
	JMP ·resume(SB)       // Restore to registers.

// See entry_amd64.go.
TEXT ·sysenter(SB),NOSPLIT,$0
	// Interrupts are always disabled while we're executing in kernel mode
	// and always enabled while executing in user mode. Therefore, we can
	// reliably look at the flags in R11 to determine where this syscall
	// was from.
	TESTL $_RFLAGS_IF, R11
	JZ kernel

user:
	SWAP_GS()
	XCHGQ CPU_REGISTERS+PTRACE_RSP(GS), SP // Swap stacks.
	XCHGQ CPU_REGISTERS+PTRACE_RAX(GS), AX // Swap for AX (regs).
	REGISTERS_SAVE(AX, 0)                  // Save all except IP, FLAGS, SP, AX.
	MOVQ CPU_REGISTERS+PTRACE_RAX(GS), BX  // Load saved AX value.
	MOVQ BX,  PTRACE_RAX(AX)               // Save everything else.
	MOVQ BX,  PTRACE_ORIGRAX(AX)
	MOVQ CX,  PTRACE_RIP(AX)
	MOVQ R11, PTRACE_FLAGS(AX)
	MOVQ CPU_REGISTERS+PTRACE_RSP(GS), BX; MOVQ BX, PTRACE_RSP(AX)
	MOVQ $0, CPU_ERROR_CODE(GS) // Clear error code.
	MOVQ $1, CPU_ERROR_TYPE(GS) // Set error type to user.

	// Return to the kernel, where the frame is:
	//
	//	vector      (sp+24)
	// 	regs        (sp+16)
	// 	cpu         (sp+8)
	// 	vcpu.Switch (sp+0)
	//
	MOVQ CPU_REGISTERS+PTRACE_RBP(GS), BP // Original base pointer.
	MOVQ $Syscall, 24(SP)                 // Output vector.
	RET

kernel:
	// We can't restore the original stack, but we can access the registers
	// in the CPU state directly. No need for temporary juggling.
	MOVQ AX,  CPU_REGISTERS+PTRACE_ORIGRAX(GS)
	MOVQ AX,  CPU_REGISTERS+PTRACE_RAX(GS)
	REGISTERS_SAVE(GS, CPU_REGISTERS)
	MOVQ CX,  CPU_REGISTERS+PTRACE_RIP(GS)
	MOVQ R11, CPU_REGISTERS+PTRACE_FLAGS(GS)
	MOVQ SP,  CPU_REGISTERS+PTRACE_RSP(GS)
	MOVQ $0, CPU_ERROR_CODE(GS) // Clear error code.
	MOVQ $0, CPU_ERROR_TYPE(GS) // Set error type to kernel.

	// Call the syscall trampoline.
	LOAD_KERNEL_STACK(GS)
	MOVQ CPU_SELF(GS), AX   // Load vCPU.
	PUSHQ AX                // First argument (vCPU).
	CALL ·kernelSyscall(SB) // Call the trampoline.
	POPQ AX                 // Pop vCPU.
	JMP ·resume(SB)

// exception is a generic exception handler.
//
// There are two cases handled:
//
// 1) An exception in kernel mode: this results in saving the state at the time
// of the exception and calling the defined hook.
//
// 2) An exception in guest mode: the original kernel frame is restored, and
// the vector & error codes are pushed as return values.
//
// See below for the stubs that call exception.
TEXT ·exception(SB),NOSPLIT,$0
	// Determine whether the exception occurred in kernel mode or user
	// mode, based on the flags. We expect the following stack:
	//
	//	SS          (sp+48)
	//	SP          (sp+40)
	//	FLAGS       (sp+32)
	//	CS          (sp+24)
	//	IP          (sp+16)
	//	ERROR_CODE  (sp+8)
	//	VECTOR      (sp+0)
	//
	TESTL $_RFLAGS_IF, 32(SP)
	JZ kernel

user:
	SWAP_GS()
	ADDQ $-8, SP                            // Adjust for flags.
	MOVQ $_KERNEL_FLAGS, 0(SP); BYTE $0x9d; // Reset flags (POPFQ).
	XCHGQ CPU_REGISTERS+PTRACE_RAX(GS), AX  // Swap for user regs.
	REGISTERS_SAVE(AX, 0)                   // Save all except IP, FLAGS, SP, AX.
	MOVQ CPU_REGISTERS+PTRACE_RAX(GS), BX   // Restore original AX.
	MOVQ BX, PTRACE_RAX(AX)                 // Save it.
	MOVQ BX, PTRACE_ORIGRAX(AX)
	MOVQ 16(SP), BX; MOVQ BX, PTRACE_RIP(AX)
	MOVQ 24(SP), CX; MOVQ CX, PTRACE_CS(AX)
	MOVQ 32(SP), DX; MOVQ DX, PTRACE_FLAGS(AX)
	MOVQ 40(SP), DI; MOVQ DI, PTRACE_RSP(AX)
	MOVQ 48(SP), SI; MOVQ SI, PTRACE_SS(AX)

	// Copy out and return.
	MOVQ 0(SP), BX                        // Load vector.
	MOVQ 8(SP), CX                        // Load error code.
	MOVQ CPU_REGISTERS+PTRACE_RSP(GS), SP // Original stack (kernel version).
	MOVQ CPU_REGISTERS+PTRACE_RBP(GS), BP // Original base pointer.
	MOVQ CX, CPU_ERROR_CODE(GS)           // Set error code.
	MOVQ $1, CPU_ERROR_TYPE(GS)           // Set error type to user.
	MOVQ BX, 24(SP)                       // Output vector.
	RET

kernel:
	// As per above, we can save directly.
	MOVQ AX, CPU_REGISTERS+PTRACE_RAX(GS)
	MOVQ AX, CPU_REGISTERS+PTRACE_ORIGRAX(GS)
	REGISTERS_SAVE(GS, CPU_REGISTERS)
	MOVQ 16(SP), AX; MOVQ AX, CPU_REGISTERS+PTRACE_RIP(GS)
	MOVQ 32(SP), BX; MOVQ BX, CPU_REGISTERS+PTRACE_FLAGS(GS)
	MOVQ 40(SP), CX; MOVQ CX, CPU_REGISTERS+PTRACE_RSP(GS)

	// Set the error code and adjust the stack.
	MOVQ 8(SP), AX              // Load the error code.
	MOVQ AX, CPU_ERROR_CODE(GS) // Copy out to the CPU.
	MOVQ $0, CPU_ERROR_TYPE(GS) // Set error type to kernel.
	MOVQ 0(SP), BX              // BX contains the vector.
	ADDQ $48, SP                // Drop the exception frame.

	// Call the exception trampoline.
	LOAD_KERNEL_STACK(GS)
	MOVQ CPU_SELF(GS), AX     // Load vCPU.
	PUSHQ BX                  // Second argument (vector).
	PUSHQ AX                  // First argument (vCPU).
	CALL ·kernelException(SB) // Call the trampoline.
	POPQ BX                   // Pop vector.
	POPQ AX                   // Pop vCPU.
	JMP ·resume(SB)

#define EXCEPTION_WITH_ERROR(value, symbol) \
TEXT symbol,NOSPLIT,$0; \
	PUSHQ $value; \
	JMP ·exception(SB);

#define EXCEPTION_WITHOUT_ERROR(value, symbol) \
TEXT symbol,NOSPLIT,$0; \
	PUSHQ $0x0; \
	PUSHQ $value; \
	JMP ·exception(SB);

EXCEPTION_WITHOUT_ERROR(DivideByZero, ·divideByZero(SB))
EXCEPTION_WITHOUT_ERROR(Debug, ·debug(SB))
EXCEPTION_WITHOUT_ERROR(NMI, ·nmi(SB))
EXCEPTION_WITHOUT_ERROR(Breakpoint, ·breakpoint(SB))
EXCEPTION_WITHOUT_ERROR(Overflow, ·overflow(SB))
EXCEPTION_WITHOUT_ERROR(BoundRangeExceeded, ·boundRangeExceeded(SB))
EXCEPTION_WITHOUT_ERROR(InvalidOpcode, ·invalidOpcode(SB))
EXCEPTION_WITHOUT_ERROR(DeviceNotAvailable, ·deviceNotAvailable(SB))
EXCEPTION_WITH_ERROR(DoubleFault, ·doubleFault(SB))
EXCEPTION_WITHOUT_ERROR(CoprocessorSegmentOverrun, ·coprocessorSegmentOverrun(SB))
EXCEPTION_WITH_ERROR(InvalidTSS, ·invalidTSS(SB))
EXCEPTION_WITH_ERROR(SegmentNotPresent, ·segmentNotPresent(SB))
EXCEPTION_WITH_ERROR(StackSegmentFault, ·stackSegmentFault(SB))
EXCEPTION_WITH_ERROR(GeneralProtectionFault, ·generalProtectionFault(SB))
EXCEPTION_WITH_ERROR(PageFault, ·pageFault(SB))
EXCEPTION_WITHOUT_ERROR(X87FloatingPointException, ·x87FloatingPointException(SB))
EXCEPTION_WITH_ERROR(AlignmentCheck, ·alignmentCheck(SB))
EXCEPTION_WITHOUT_ERROR(MachineCheck, ·machineCheck(SB))
EXCEPTION_WITHOUT_ERROR(SIMDFloatingPointException, ·simdFloatingPointException(SB))
EXCEPTION_WITHOUT_ERROR(VirtualizationException, ·virtualizationException(SB))
EXCEPTION_WITH_ERROR(SecurityException, ·securityException(SB))
EXCEPTION_WITHOUT_ERROR(SyscallInt80, ·syscallInt80(SB))
