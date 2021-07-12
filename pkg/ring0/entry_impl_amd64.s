// build +amd64

// Automatically generated, do not edit.

// CPU offsets.
#define CPU_REGISTERS        0x28
#define CPU_ERROR_CODE       0x10
#define CPU_ERROR_TYPE       0x18
#define CPU_ENTRY            0x20

// CPU entry offsets.
#define ENTRY_SCRATCH0       0x100
#define ENTRY_STACK_TOP      0x108
#define ENTRY_CPU_SELF       0x110
#define ENTRY_KERNEL_CR3     0x118

// Bits.
#define _RFLAGS_IF           0x200
#define _RFLAGS_IOPL0         0x1000
#define _KERNEL_FLAGS        0x02

// Vectors.
#define DivideByZero               0x00
#define Debug                      0x01
#define NMI                        0x02
#define Breakpoint                 0x03
#define Overflow                   0x04
#define BoundRangeExceeded         0x05
#define InvalidOpcode              0x06
#define DeviceNotAvailable         0x07
#define DoubleFault                0x08
#define CoprocessorSegmentOverrun  0x09
#define InvalidTSS                 0x0a
#define SegmentNotPresent          0x0b
#define StackSegmentFault          0x0c
#define GeneralProtectionFault     0x0d
#define PageFault                  0x0e
#define X87FloatingPointException  0x10
#define AlignmentCheck             0x11
#define MachineCheck               0x12
#define SIMDFloatingPointException 0x13
#define VirtualizationException    0x14
#define SecurityException          0x1e
#define SyscallInt80               0x80
#define Syscall                    0x100

// Ptrace registers.
#define PTRACE_R15      0x00
#define PTRACE_R14      0x08
#define PTRACE_R13      0x10
#define PTRACE_R12      0x18
#define PTRACE_RBP      0x20
#define PTRACE_RBX      0x28
#define PTRACE_R11      0x30
#define PTRACE_R10      0x38
#define PTRACE_R9       0x40
#define PTRACE_R8       0x48
#define PTRACE_RAX      0x50
#define PTRACE_RCX      0x58
#define PTRACE_RDX      0x60
#define PTRACE_RSI      0x68
#define PTRACE_RDI      0x70
#define PTRACE_ORIGRAX  0x78
#define PTRACE_RIP      0x80
#define PTRACE_CS       0x88
#define PTRACE_FLAGS    0x90
#define PTRACE_RSP      0x98
#define PTRACE_SS       0xa0
#define PTRACE_FS_BASE  0xa8
#define PTRACE_GS_BASE  0xb0
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

// NB: Offsets are programmatically generated (see BUILD).
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

// WRITE_CR3() writes the given CR3 value.
//
// The code corresponds to:
//
//     mov %rax, %cr3
//
#define WRITE_CR3() \
	BYTE $0x0f; BYTE $0x22; BYTE $0xd8;

// SWAP_GS swaps the kernel GS (CPU).
#define SWAP_GS() \
	BYTE $0x0F; BYTE $0x01; BYTE $0xf8;

// IRET returns from an interrupt frame.
#define IRET() \
	BYTE $0x48; BYTE $0xcf;

// SYSRET64 executes the sysret instruction.
#define SYSRET64() \
	BYTE $0x48; BYTE $0x0f; BYTE $0x07;

// LOAD_KERNEL_STACK loads the kernel stack.
#define LOAD_KERNEL_STACK(entry) \
	MOVQ ENTRY_STACK_TOP(entry), SP;

// ADDR_OF_FUNC defines a function named 'name' that returns the address of
// 'symbol'.
#define ADDR_OF_FUNC(name, symbol) \
TEXT name,$0-8; \
	MOVQ $symbol, AX; \
	MOVQ AX, ret+0(FP); \
	RET

// See kernel.go.
TEXT ·Halt(SB),NOSPLIT,$0
	HLT
	RET

// See kernel_amd64.go.
TEXT ·HaltAndWriteFSBase(SB),NOSPLIT,$8-8
	HLT

	// Restore FS_BASE.
	MOVQ regs+0(FP), AX
	MOVQ PTRACE_FS_BASE(AX), AX

	PUSHQ AX  // First argument (FS_BASE)
	CALL ·writeFS(SB)
	POPQ AX

	RET

// See entry_amd64.go.
TEXT ·swapgs(SB),NOSPLIT,$0
	SWAP_GS()
	RET

// jumpToKernel changes execution to the kernel address space.
//
// This works by changing the return value to the kernel version.
TEXT ·jumpToKernel(SB),NOSPLIT,$0
	MOVQ 0(SP), AX
	ORQ ·KernelStartAddress(SB), AX // Future return value.
	MOVQ AX, 0(SP)
	RET

// jumpToUser changes execution to the user address space.
//
// This works by changing the return value to the user version.
TEXT ·jumpToUser(SB),NOSPLIT,$0
	// N.B. we can't access KernelStartAddress from the upper half (data
	// pages not available), so just naively clear all the upper bits.
	// We are assuming a 47-bit virtual address space.
	MOVQ $0x00007fffffffffff, AX
	MOVQ 0(SP), BX
	ANDQ BX, AX // Future return value.
	MOVQ AX, 0(SP)
	RET

// See entry_amd64.go.
TEXT ·sysret(SB),NOSPLIT,$0-24
	// Set application FS. We can't do this in Go because Go code needs FS.
	MOVQ regs+8(FP), AX
	MOVQ PTRACE_FS_BASE(AX), AX

	PUSHQ AX
	CALL ·writeFS(SB)
	POPQ AX

	CALL ·jumpToKernel(SB)
	// Save original state and stack. sysenter() or exception()
	// from APP(gr3) will switch to this stack, set the return
	// value (vector: 32(SP)) and then do RET, which will also
	// automatically return to the lower half.
	MOVQ cpu+0(FP), BX
	MOVQ regs+8(FP), AX
	MOVQ userCR3+16(FP), CX
	MOVQ SP, CPU_REGISTERS+PTRACE_RSP(BX)
	MOVQ BP, CPU_REGISTERS+PTRACE_RBP(BX)
	MOVQ AX, CPU_REGISTERS+PTRACE_RAX(BX)

	// save SP AX userCR3 on the kernel stack.
	MOVQ CPU_ENTRY(BX), BX
	LOAD_KERNEL_STACK(BX)
	PUSHQ PTRACE_RSP(AX)
	PUSHQ PTRACE_RAX(AX)
	PUSHQ CX

	// Restore user register state.
	REGISTERS_LOAD(AX, 0)
	MOVQ PTRACE_RIP(AX), CX    // Needed for SYSRET.
	MOVQ PTRACE_FLAGS(AX), R11 // Needed for SYSRET.

	// restore userCR3, AX, SP.
	POPQ AX	                            // Get userCR3.
	WRITE_CR3()                         // Switch to userCR3.
	POPQ AX                             // Restore AX.
	POPQ SP                             // Restore SP.
	SYSRET64()

// See entry_amd64.go.
TEXT ·iret(SB),NOSPLIT,$0-24
	// Set application FS. We can't do this in Go because Go code needs FS.
	MOVQ regs+8(FP), AX
	MOVQ PTRACE_FS_BASE(AX), AX

	PUSHQ AX // First argument (FS_BASE)
	CALL ·writeFS(SB)
	POPQ AX

	CALL ·jumpToKernel(SB)
	// Save original state and stack. sysenter() or exception()
	// from APP(gr3) will switch to this stack, set the return
	// value (vector: 32(SP)) and then do RET, which will also
	// automatically return to the lower half.
	MOVQ cpu+0(FP), BX
	MOVQ regs+8(FP), AX
	MOVQ userCR3+16(FP), CX
	MOVQ SP, CPU_REGISTERS+PTRACE_RSP(BX)
	MOVQ BP, CPU_REGISTERS+PTRACE_RBP(BX)
	MOVQ AX, CPU_REGISTERS+PTRACE_RAX(BX)

	// Build an IRET frame & restore state.
	MOVQ CPU_ENTRY(BX), BX
	LOAD_KERNEL_STACK(BX)
	PUSHQ PTRACE_SS(AX)
	PUSHQ PTRACE_RSP(AX)
	PUSHQ PTRACE_FLAGS(AX)
	PUSHQ PTRACE_CS(AX)
	PUSHQ PTRACE_RIP(AX)
	PUSHQ PTRACE_RAX(AX)                // Save AX on kernel stack.
	PUSHQ CX                            // Save userCR3 on kernel stack.
	REGISTERS_LOAD(AX, 0)               // Restore most registers.
	POPQ AX	                            // Get userCR3.
	WRITE_CR3()                         // Switch to userCR3.
	POPQ AX                             // Restore AX.
	IRET()

// See entry_amd64.go.
TEXT ·resume(SB),NOSPLIT,$0
	// See iret, above.
	MOVQ ENTRY_CPU_SELF(GS), AX                 // Load vCPU.
	PUSHQ CPU_REGISTERS+PTRACE_SS(AX)
	PUSHQ CPU_REGISTERS+PTRACE_RSP(AX)
	PUSHQ CPU_REGISTERS+PTRACE_FLAGS(AX)
	PUSHQ CPU_REGISTERS+PTRACE_CS(AX)
	PUSHQ CPU_REGISTERS+PTRACE_RIP(AX)
	REGISTERS_LOAD(AX, CPU_REGISTERS)
	MOVQ CPU_REGISTERS+PTRACE_RAX(AX), AX
	IRET()

// See entry_amd64.go.
TEXT ·start(SB),NOSPLIT,$0
	// N.B. This is the vCPU entrypoint. It is not called from Go code and
	// thus pushes and pops values on the stack until calling into Go
	// (startGo) because we aren't usually a typical Go assembly frame.

	PUSHQ $0x0            // Previous frame pointer.
	MOVQ SP, BP           // Set frame pointer.

	PUSHQ AX              // Save CPU.

	// Set up environment required by Go before calling startGo: Go needs
	// FS_BASE and floating point initialized.
	MOVQ CPU_REGISTERS+PTRACE_FS_BASE(AX), BX
	PUSHQ BX              // First argument (FS_BASE)
	CALL ·writeFS(SB)
	POPQ BX

	// First argument (CPU) already at bottom of stack.
	CALL ·startGo(SB)     // Call Go hook.
	JMP ·resume(SB)       // Restore to registers.

ADDR_OF_FUNC(·AddrOfStart(SB), ·start(SB));

// See entry_amd64.go.
TEXT ·sysenter(SB),NOSPLIT,$0
	// _RFLAGS_IOPL0 is always set in the user mode and it is never set in
	// the kernel mode. See the comment of UserFlagsSet for more details.
	TESTL $_RFLAGS_IOPL0, R11
	JZ kernel
user:
	SWAP_GS()
	MOVQ AX, ENTRY_SCRATCH0(GS)            // Save user AX on scratch.
	MOVQ ENTRY_KERNEL_CR3(GS), AX          // Get kernel cr3 on AX.
	WRITE_CR3()                            // Switch to kernel cr3.

	MOVQ ENTRY_CPU_SELF(GS), AX            // Load vCPU.
	MOVQ CPU_REGISTERS+PTRACE_RAX(AX), AX  // Get user regs.
	REGISTERS_SAVE(AX, 0)                  // Save all except IP, FLAGS, SP, AX.
	MOVQ CX,  PTRACE_RIP(AX)
	MOVQ R11, PTRACE_FLAGS(AX)
	MOVQ SP,  PTRACE_RSP(AX)
	MOVQ ENTRY_SCRATCH0(GS), CX            // Load saved user AX value.
	MOVQ CX,  PTRACE_RAX(AX)               // Save everything else.
	MOVQ CX,  PTRACE_ORIGRAX(AX)

	MOVQ ENTRY_CPU_SELF(GS), AX            // Load vCPU.
	MOVQ CPU_REGISTERS+PTRACE_RSP(AX), SP  // Get stacks.
	MOVQ $0, CPU_ERROR_CODE(AX)            // Clear error code.
	MOVQ $1, CPU_ERROR_TYPE(AX)            // Set error type to user.

	CALL ·jumpToUser(SB)

	// Restore kernel FS_BASE.
	MOVQ ENTRY_CPU_SELF(GS), AX            // Load vCPU.
	MOVQ CPU_REGISTERS+PTRACE_FS_BASE(AX), BX

	PUSHQ BX                               // First argument (FS_BASE)
	CALL ·writeFS(SB)
	POPQ BX

	MOVQ ENTRY_CPU_SELF(GS), AX            // Load vCPU.

	// Return to the kernel, where the frame is:
	//
	//	vector      (sp+32)
	//	userCR3     (sp+24)
	// 	regs        (sp+16)
	// 	cpu         (sp+8)
	// 	vcpu.Switch (sp+0)
	//
	MOVQ CPU_REGISTERS+PTRACE_RBP(AX), BP // Original base pointer.
	MOVQ $Syscall, 32(SP)                 // Output vector.
	RET

kernel:
	// We can't restore the original stack, but we can access the registers
	// in the CPU state directly. No need for temporary juggling.
	MOVQ AX,  ENTRY_SCRATCH0(GS)
	MOVQ ENTRY_CPU_SELF(GS), AX                 // Load vCPU.
	REGISTERS_SAVE(AX, CPU_REGISTERS)
	MOVQ CX,  CPU_REGISTERS+PTRACE_RIP(AX)
	MOVQ R11, CPU_REGISTERS+PTRACE_FLAGS(AX)
	MOVQ SP,  CPU_REGISTERS+PTRACE_RSP(AX)
	MOVQ ENTRY_SCRATCH0(GS), BX
	MOVQ BX,  CPU_REGISTERS+PTRACE_ORIGRAX(AX)
	MOVQ BX,  CPU_REGISTERS+PTRACE_RAX(AX)
	MOVQ $0,  CPU_ERROR_CODE(AX)                // Clear error code.
	MOVQ $0,  CPU_ERROR_TYPE(AX)                // Set error type to kernel.

	// Call the syscall trampoline.
	LOAD_KERNEL_STACK(GS)
	PUSHQ AX                // First argument (vCPU).
	CALL ·kernelSyscall(SB) // Call the trampoline.
	POPQ AX                 // Pop vCPU.
	JMP ·resume(SB)

ADDR_OF_FUNC(·addrOfSysenter(SB), ·sysenter(SB));

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
	TESTL $_RFLAGS_IOPL0, 32(SP)
	JZ kernel

user:
	SWAP_GS()
	ADDQ $-8, SP                            // Adjust for flags.
	MOVQ $_KERNEL_FLAGS, 0(SP); BYTE $0x9d; // Reset flags (POPFQ).
	PUSHQ AX                                // Save user AX on stack.
	MOVQ ENTRY_KERNEL_CR3(GS), AX           // Get kernel cr3 on AX.
	WRITE_CR3()                             // Switch to kernel cr3.

	MOVQ ENTRY_CPU_SELF(GS), AX             // Load vCPU.
	MOVQ CPU_REGISTERS+PTRACE_RAX(AX), AX   // Get user regs.
	REGISTERS_SAVE(AX, 0)                   // Save all except IP, FLAGS, SP, AX.
	POPQ BX                                 // Restore original AX.
	MOVQ BX, PTRACE_RAX(AX)                 // Save it.
	MOVQ BX, PTRACE_ORIGRAX(AX)
	MOVQ 16(SP), BX; MOVQ BX, PTRACE_RIP(AX)
	MOVQ 24(SP), CX; MOVQ CX, PTRACE_CS(AX)
	MOVQ 32(SP), DX; MOVQ DX, PTRACE_FLAGS(AX)
	MOVQ 40(SP), DI; MOVQ DI, PTRACE_RSP(AX)
	MOVQ 48(SP), SI; MOVQ SI, PTRACE_SS(AX)

	CALL ·jumpToUser(SB)

	// Restore kernel FS_BASE.
	MOVQ ENTRY_CPU_SELF(GS), AX            // Load vCPU.
	MOVQ CPU_REGISTERS+PTRACE_FS_BASE(AX), BX

	PUSHQ BX                               // First argument (FS_BASE)
	CALL ·writeFS(SB)
	POPQ BX

	// Copy out and return.
	MOVQ ENTRY_CPU_SELF(GS), AX           // Load vCPU.
	MOVQ 0(SP), BX                        // Load vector.
	MOVQ 8(SP), CX                        // Load error code.
	MOVQ CPU_REGISTERS+PTRACE_RSP(AX), SP // Original stack (kernel version).
	MOVQ CPU_REGISTERS+PTRACE_RBP(AX), BP // Original base pointer.
	MOVQ CX, CPU_ERROR_CODE(AX)           // Set error code.
	MOVQ $1, CPU_ERROR_TYPE(AX)           // Set error type to user.
	MOVQ BX, 32(SP)                       // Output vector.
	RET

kernel:
	// As per above, we can save directly.
	PUSHQ AX
	MOVQ ENTRY_CPU_SELF(GS), AX                        // Load vCPU.
	REGISTERS_SAVE(AX, CPU_REGISTERS)
	POPQ BX
	MOVQ BX, CPU_REGISTERS+PTRACE_RAX(AX)
	MOVQ BX, CPU_REGISTERS+PTRACE_ORIGRAX(AX)
	MOVQ 16(SP), BX; MOVQ BX, CPU_REGISTERS+PTRACE_RIP(AX)
	MOVQ 32(SP), BX; MOVQ BX, CPU_REGISTERS+PTRACE_FLAGS(AX)
	MOVQ 40(SP), BX; MOVQ BX, CPU_REGISTERS+PTRACE_RSP(AX)

	// Set the error code and adjust the stack.
	MOVQ 8(SP), BX              // Load the error code.
	MOVQ BX, CPU_ERROR_CODE(AX) // Copy out to the CPU.
	MOVQ $0, CPU_ERROR_TYPE(AX) // Set error type to kernel.
	MOVQ 0(SP), BX              // BX contains the vector.

	// Call the exception trampoline.
	LOAD_KERNEL_STACK(GS)
	PUSHQ BX                  // Second argument (vector).
	PUSHQ AX                  // First argument (vCPU).
	CALL ·kernelException(SB) // Call the trampoline.
	POPQ BX                   // Pop vector.
	POPQ AX                   // Pop vCPU.
	JMP ·resume(SB)

#define EXCEPTION_WITH_ERROR(value, symbol, addr) \
ADDR_OF_FUNC(addr, symbol); \
TEXT symbol,NOSPLIT,$0; \
	PUSHQ $value; \
	JMP ·exception(SB);

#define EXCEPTION_WITHOUT_ERROR(value, symbol, addr) \
ADDR_OF_FUNC(addr, symbol); \
TEXT symbol,NOSPLIT,$0; \
	PUSHQ $0x0; \
	PUSHQ $value; \
	JMP ·exception(SB);

EXCEPTION_WITHOUT_ERROR(DivideByZero, ·divideByZero(SB), ·addrOfDivideByZero(SB))
EXCEPTION_WITHOUT_ERROR(Debug, ·debug(SB), ·addrOfDebug(SB))
EXCEPTION_WITHOUT_ERROR(NMI, ·nmi(SB), ·addrOfNMI(SB))
EXCEPTION_WITHOUT_ERROR(Breakpoint, ·breakpoint(SB), ·addrOfBreakpoint(SB))
EXCEPTION_WITHOUT_ERROR(Overflow, ·overflow(SB), ·addrOfOverflow(SB))
EXCEPTION_WITHOUT_ERROR(BoundRangeExceeded, ·boundRangeExceeded(SB), ·addrOfBoundRangeExceeded(SB))
EXCEPTION_WITHOUT_ERROR(InvalidOpcode, ·invalidOpcode(SB), ·addrOfInvalidOpcode(SB))
EXCEPTION_WITHOUT_ERROR(DeviceNotAvailable, ·deviceNotAvailable(SB), ·addrOfDeviceNotAvailable(SB))
EXCEPTION_WITH_ERROR(DoubleFault, ·doubleFault(SB), ·addrOfDoubleFault(SB))
EXCEPTION_WITHOUT_ERROR(CoprocessorSegmentOverrun, ·coprocessorSegmentOverrun(SB), ·addrOfCoprocessorSegmentOverrun(SB))
EXCEPTION_WITH_ERROR(InvalidTSS, ·invalidTSS(SB), ·addrOfInvalidTSS(SB))
EXCEPTION_WITH_ERROR(SegmentNotPresent, ·segmentNotPresent(SB), ·addrOfSegmentNotPresent(SB))
EXCEPTION_WITH_ERROR(StackSegmentFault, ·stackSegmentFault(SB), ·addrOfStackSegmentFault(SB))
EXCEPTION_WITH_ERROR(GeneralProtectionFault, ·generalProtectionFault(SB), ·addrOfGeneralProtectionFault(SB))
EXCEPTION_WITH_ERROR(PageFault, ·pageFault(SB), ·addrOfPageFault(SB))
EXCEPTION_WITHOUT_ERROR(X87FloatingPointException, ·x87FloatingPointException(SB), ·addrOfX87FloatingPointException(SB))
EXCEPTION_WITH_ERROR(AlignmentCheck, ·alignmentCheck(SB), ·addrOfAlignmentCheck(SB))
EXCEPTION_WITHOUT_ERROR(MachineCheck, ·machineCheck(SB), ·addrOfMachineCheck(SB))
EXCEPTION_WITHOUT_ERROR(SIMDFloatingPointException, ·simdFloatingPointException(SB), ·addrOfSimdFloatingPointException(SB))
EXCEPTION_WITHOUT_ERROR(VirtualizationException, ·virtualizationException(SB), ·addrOfVirtualizationException(SB))
EXCEPTION_WITH_ERROR(SecurityException, ·securityException(SB), ·addrOfSecurityException(SB))
EXCEPTION_WITHOUT_ERROR(SyscallInt80, ·syscallInt80(SB), ·addrOfSyscallInt80(SB))
