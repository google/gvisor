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

// See kernel_amd64.go.
//
// The 16-byte frame size is for the saved values of MXCSR and the x87 control
// word.
TEXT ·doSwitchToUser(SB),NOSPLIT,$16-48
	// We are passed pointers to heap objects, but do not store them in our
	// local frame.
	NO_LOCAL_POINTERS

	// MXCSR and the x87 control word are the only floating point state
	// that is callee-save and thus we must save.
	STMXCSR mxcsr-0(SP)
	FSTCW cw-8(SP)

	// Restore application floating point state.
	MOVQ cpu+0(FP), SI
	MOVQ fpState+16(FP), DI
	MOVB ·hasXSAVE(SB), BX
	TESTB BX, BX
	JZ no_xrstor
	// Use xrstor to restore all available fp state. For now, we restore
	// everything unconditionally by setting the implicit operand edx:eax
	// (the "requested feature bitmap") to all 1's.
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x2f // XRSTOR64 0(DI)
	JMP fprestore_done
no_xrstor:
	// Fall back to fxrstor if xsave is not available.
	FXRSTOR64 0(DI)
fprestore_done:

	// Set application GS.
	MOVQ regs+8(FP), R8
	SWAP_GS()
	MOVQ PTRACE_GS_BASE(R8), AX
	PUSHQ AX
	CALL ·writeGS(SB)
	POPQ AX

	// Call sysret() or iret().
	MOVQ userCR3+24(FP), CX
	MOVQ needIRET+32(FP), R9
	ADDQ $-32, SP
	MOVQ SI, 0(SP)  // cpu
	MOVQ R8, 8(SP)  // regs
	MOVQ CX, 16(SP) // userCR3
	TESTQ R9, R9
	JNZ do_iret
	CALL ·sysret(SB)
	JMP done_sysret_or_iret
do_iret:
	CALL ·iret(SB)
done_sysret_or_iret:
	MOVQ 24(SP), AX // vector
	ADDQ $32, SP
	MOVQ AX, vector+40(FP)

	// Save application floating point state.
	MOVQ fpState+16(FP), DI
	MOVB ·hasXSAVE(SB), BX
	MOVB ·hasXSAVEOPT(SB), CX
	TESTB BX, BX
	JZ no_xsave
	// Use xsave/xsaveopt to save all extended state.
	// We save everything unconditionally by setting RFBM to all 1's.
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	TESTB CX, CX
	JZ no_xsaveopt
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x37; // XSAVEOPT64 0(DI)
	JMP fpsave_done
no_xsaveopt:
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x27; // XSAVE64 0(DI)
	JMP fpsave_done
no_xsave:
	FXSAVE64 0(DI)
fpsave_done:

	// Restore MXCSR and the x87 control word after one of the two floating
	// point save cases above, to ensure the application versions are saved
	// before being clobbered here.
	LDMXCSR mxcsr-0(SP)

	// FLDCW is a "waiting" x87 instruction, meaning it checks for pending
	// unmasked exceptions before executing. Thus if userspace has unmasked
	// an exception and has one pending, it can be raised by FLDCW even
	// though the new control word will mask exceptions. To prevent this,
	// we must first clear pending exceptions (which will be restored by
	// XRSTOR, et al).
	BYTE $0xDB; BYTE $0xE2; // FNCLEX
	FLDCW cw-8(SP)

	RET

// See entry_amd64.go.
TEXT ·sysret(SB),NOSPLIT,$0-32
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
	// sysenter or exception will write our return value and return to our
	// caller.

// See entry_amd64.go.
TEXT ·iret(SB),NOSPLIT,$0-32
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
	// sysenter or exception will write our return value and return to our
	// caller.

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

	// Save floating point state. CPU.floatingPointState is a slice, so the
	// first word of CPU.floatingPointState is a pointer to the destination
	// array.
	MOVQ CPU_FPU_STATE(AX), DI
	MOVB CPU_HAS_XSAVE(AX), BX
	MOVB CPU_HAS_XSAVEOPT(AX), CX
	TESTB BX, BX
	JZ no_xsave
	// Use xsave/xsaveopt to save all extended state.
	// We save everything unconditionally by setting RFBM to all 1's.
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	TESTB CX, CX
	JZ no_xsaveopt
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x37; // XSAVEOPT64 0(DI)
	JMP fpsave_done
no_xsaveopt:
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x27; // XSAVE64 0(DI)
	JMP fpsave_done
no_xsave:
	FXSAVE64 0(DI)
fpsave_done:

	// Call the syscall trampoline.
	LOAD_KERNEL_STACK(GS)
	MOVQ ENTRY_CPU_SELF(GS), AX // AX contains the vCPU.
	PUSHQ AX                    // First argument (vCPU).
	CALL ·kernelSyscall(SB)     // Call the trampoline.
	POPQ AX                     // Pop vCPU.

	// We only trigger a bluepill entry in the bluepill function, and can
	// therefore be guaranteed that there is no floating point state to be
	// loaded on resuming from halt.
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

	// Save floating point state. CPU.floatingPointState is a slice, so the
	// first word of CPU.floatingPointState is a pointer to the destination
	// array.
	MOVQ CPU_FPU_STATE(AX), DI
	MOVB CPU_HAS_XSAVE(AX), BX
	MOVB CPU_HAS_XSAVEOPT(AX), CX
	TESTB BX, BX
	JZ no_xsave
	// Use xsave/xsaveopt to save all extended state.
	// We save everything unconditionally by setting RFBM to all 1's.
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	TESTB CX, CX
	JZ no_xsaveopt
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x37; // XSAVEOPT64 0(DI)
	JMP fpsave_done
no_xsaveopt:
	BYTE $0x48; BYTE $0x0f; BYTE $0xae; BYTE $0x27; // XSAVE64 0(DI)
	JMP fpsave_done
no_xsave:
	FXSAVE64 0(DI)
fpsave_done:

	// Call the exception trampoline.
	MOVQ 0(SP), BX              // BX contains the vector.
	LOAD_KERNEL_STACK(GS)
	MOVQ ENTRY_CPU_SELF(GS), AX // AX contains the vCPU.
	PUSHQ BX                    // Second argument (vector).
	PUSHQ AX                    // First argument (vCPU).
	CALL ·kernelException(SB)   // Call the trampoline.
	POPQ BX                     // Pop vector.
	POPQ AX                     // Pop vCPU.

	// We only trigger a bluepill entry in the bluepill function, and can
	// therefore be guaranteed that there is no floating point state to be
	// loaded on resuming from halt.
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
