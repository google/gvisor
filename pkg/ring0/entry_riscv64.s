#include "funcdata.h"
#include "textflag.h"

#define CPU_SELF             0   // +checkoffset . CPU.self
#define CPU_REGISTERS        216 // +checkoffset . CPU.registers
#define CPU_FPSTATE	     480 // +checkoffset . CPU.floatingPointState
#define CPU_ARCH_STATE       16  // +checkoffset . CPU.CPUArchState
#define CPU_STACK_BOTTOM     CPU_ARCH_STATE+0     // +checkoffset . CPUArchState.stack
#define CPU_STACK_TOP        CPU_STACK_BOTTOM+128 // +checksize . CPUArchState.stack
#define CPU_ERROR_CODE	     CPU_ARCH_STATE+128   // +checkoffset . CPUArchState.errorCode
#define CPU_ERROR_TYPE	     CPU_ARCH_STATE+136   // +checkoffset . CPUArchState.errorType
#define CPU_FAULT_ADDR	     CPU_ARCH_STATE+144   // +checkoffset . CPUArchState.faultAddr
#define CPU_APP_FPSTATE	     CPU_ARCH_STATE+152   // +checkoffset . CPUArchState.fpstateApp
#define CPU_SATP_KVM	     CPU_ARCH_STATE+160   // +checkoffset . CPUArchState.satpKvm
#define CPU_SATP_APP	     CPU_ARCH_STATE+168   // +checkoffset . CPUArchState.satpApp
#define CPU_VECTOR_CODE	     CPU_ARCH_STATE+176   // +checkoffset . CPUArchState.vecCode
#define CPU_APP_ADDR	     CPU_ARCH_STATE+184   // +checkoffset . CPUArchState.appAddr
#define CPU_APP_ASID         CPU_ARCH_STATE+192   // +checkoffset . CPUArchState.appASID

#define SRET WORD $0x10200073

#define PTRACE_REGS	0 // +checkoffset linux PtraceRegs.Regs
#define PTRACE_PC	(PTRACE_REGS + 0*8)
#define PTRACE_RA	(PTRACE_REGS + 1*8)
#define PTRACE_SP	(PTRACE_REGS + 2*8)
#define PTRACE_GP	(PTRACE_REGS + 3*8)
#define PTRACE_TP	(PTRACE_REGS + 4*8)
#define PTRACE_T0	(PTRACE_REGS + 5*8)
#define PTRACE_T1	(PTRACE_REGS + 6*8)
#define PTRACE_T2	(PTRACE_REGS + 7*8)
#define PTRACE_S0	(PTRACE_REGS + 8*8)
#define PTRACE_S1	(PTRACE_REGS + 9*8)
#define PTRACE_A0	(PTRACE_REGS + 10*8)
#define PTRACE_A1	(PTRACE_REGS + 11*8)
#define PTRACE_A2	(PTRACE_REGS + 12*8)
#define PTRACE_A3	(PTRACE_REGS + 13*8)
#define PTRACE_A4	(PTRACE_REGS + 14*8)
#define PTRACE_A5	(PTRACE_REGS + 15*8)
#define PTRACE_A6	(PTRACE_REGS + 16*8)
#define PTRACE_A7	(PTRACE_REGS + 17*8)
#define PTRACE_S2	(PTRACE_REGS + 18*8)
#define PTRACE_S3	(PTRACE_REGS + 19*8)
#define PTRACE_S4	(PTRACE_REGS + 20*8)
#define PTRACE_S5	(PTRACE_REGS + 21*8)
#define PTRACE_S6	(PTRACE_REGS + 22*8)
#define PTRACE_S7	(PTRACE_REGS + 23*8)
#define PTRACE_S8	(PTRACE_REGS + 24*8)
#define PTRACE_S9	(PTRACE_REGS + 25*8)
#define PTRACE_S10	(PTRACE_REGS + 26*8)
#define PTRACE_S11	(PTRACE_REGS + 27*8)
#define PTRACE_T3	(PTRACE_REGS + 28*8)
#define PTRACE_T4	(PTRACE_REGS + 29*8)
#define PTRACE_T5	(PTRACE_REGS + 30*8)
#define PTRACE_T6	(PTRACE_REGS + 31*8)
#define PTRACE_ORIGA0	(PTRACE_REGS + 32*8)

// LOAD_KERNEL_ADDRESS loads a kernel address.
#define LOAD_KERNEL_ADDRESS(from, to) \
	LUI  $-0x80000, to; \
	SLLI $0x10, to; \
	OR   from, to, to;	

// LOAD_KERNEL_STACK loads the kernel temporary stack.
#define LOAD_KERNEL_STACK \
	MOV $CPU_STACK_TOP(TP), SP;

// Saves a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
#define REGISTERS_SAVE(reg, offset) \
  MOV T0, offset+PTRACE_T0(reg); \
  REGISTERS_SAVE_EXCEPT_T0(reg, offset);

#define REGISTERS_SAVE_EXCEPT_T0(reg, offset) \
  MOV RA, offset+PTRACE_RA(reg); \
  MOV SP, offset+PTRACE_SP(reg); \
  MOV GP, offset+PTRACE_GP(reg); \
  MOV T1, offset+PTRACE_T1(reg); \
  MOV T2, offset+PTRACE_T2(reg); \
  MOV S0, offset+PTRACE_S0(reg); \
  MOV S1, offset+PTRACE_S1(reg); \
  MOV A0, offset+PTRACE_A0(reg); \
  MOV A1, offset+PTRACE_A1(reg); \
  MOV A2, offset+PTRACE_A2(reg); \
  MOV A3, offset+PTRACE_A3(reg); \
  MOV A4, offset+PTRACE_A4(reg); \
  MOV A5, offset+PTRACE_A5(reg); \
  MOV A6, offset+PTRACE_A6(reg); \
  MOV A7, offset+PTRACE_A7(reg); \
  MOV S2, offset+PTRACE_S2(reg); \
  MOV S3, offset+PTRACE_S3(reg); \
  MOV S4, offset+PTRACE_S4(reg); \
  MOV S5, offset+PTRACE_S5(reg); \
  MOV S6, offset+PTRACE_S6(reg); \
  MOV S7, offset+PTRACE_S7(reg); \
  MOV S8, offset+PTRACE_S8(reg); \
  MOV S9, offset+PTRACE_S9(reg); \
  MOV S10, offset+PTRACE_S10(reg); \
  MOV g, offset+PTRACE_S11(reg); \
  MOV T3, offset+PTRACE_T3(reg); \
  MOV T4, offset+PTRACE_T4(reg); \
  MOV T5, offset+PTRACE_T5(reg); \
  MOV T6, offset+PTRACE_T6(reg); \
  MOV A0, offset+PTRACE_ORIGA0(reg); 

#define FPREGS_LOAD(reg) \
  MOVD 0(reg), F0; \
  MOVD 8(reg), F1; \
  MOVD 16(reg), F2; \
  MOVD 24(reg), F3; \
  MOVD 32(reg), F4; \
  MOVD 40(reg), F5; \
  MOVD 48(reg), F6; \
  MOVD 56(reg), F7; \
  MOVD 64(reg), F8; \
  MOVD 72(reg), F9; \
  MOVD 80(reg), F10; \
  MOVD 88(reg), F11; \
  MOVD 96(reg), F12; \
  MOVD 104(reg), F13; \
  MOVD 112(reg), F14; \
  MOVD 120(reg), F15; \
  MOVD 128(reg), F16; \
  MOVD 136(reg), F17; \
  MOVD 144(reg), F18; \
  MOVD 152(reg), F19; \
  MOVD 160(reg), F20; \
  MOVD 168(reg), F21; \
  MOVD 176(reg), F22; \
  MOVD 184(reg), F23; \
  MOVD 192(reg), F24; \
  MOVD 200(reg), F25; \
  MOVD 208(reg), F26; \
  MOVD 216(reg), F27; \
  MOVD 224(reg), F28; \
  MOVD 232(reg), F29; \
  MOVD 240(reg), F30; \
  MOVD 248(reg), F31; \
  MOVW 256(reg), A1
  WORD $0x00359073; // fscsr a1 

#define FPREGS_SAVE(reg) \
  MOVD F0, 0(reg); \
  MOVD F1, 8(reg); \
  MOVD F2, 16(reg); \
  MOVD F3, 24(reg); \
  MOVD F4, 32(reg); \
  MOVD F5, 40(reg); \
  MOVD F6, 48(reg); \
  MOVD F7, 56(reg); \
  MOVD F8, 64(reg); \
  MOVD F9, 72(reg); \
  MOVD F10, 80(reg); \
  MOVD F11, 88(reg); \
  MOVD F12, 96(reg); \
  MOVD F13, 104(reg); \
  MOVD F14, 112(reg); \
  MOVD F15, 120(reg); \
  MOVD F16, 128(reg); \
  MOVD F17, 136(reg); \
  MOVD F18, 144(reg); \
  MOVD F19, 152(reg); \
  MOVD F20, 160(reg); \
  MOVD F21, 168(reg); \
  MOVD F22, 176(reg); \
  MOVD F23, 184(reg); \
  MOVD F24, 192(reg); \
  MOVD F25, 200(reg); \
  MOVD F26, 208(reg); \
  MOVD F27, 216(reg); \
  MOVD F28, 224(reg); \
  MOVD F29, 232(reg); \
  MOVD F30, 240(reg); \
  MOVD F31, 248(reg); \
  WORD $0x003025f3; \ // frcsr a1
  MOVW A1, 256(reg);

// Loads a register set.
//
// This is a macro because it may need to executed in contents where a stack is
// not available for calls.
//
// S11 is the g register.
#define REGISTERS_LOAD(reg, offset) \
  MOV offset+PTRACE_T0(reg), T0; \
  REGISTERS_LOAD_EXCEPT_T0(reg, offset);

#define REGISTERS_LOAD_EXCEPT_T0(reg, offset) \
  MOV offset+PTRACE_RA(reg), RA; \
  MOV offset+PTRACE_SP(reg), SP; \
  MOV offset+PTRACE_GP(reg), GP; \
  MOV offset+PTRACE_T1(reg), T1; \
  MOV offset+PTRACE_T2(reg), T2; \
  MOV offset+PTRACE_S0(reg), S0; \
  MOV offset+PTRACE_S1(reg), S1; \
  MOV offset+PTRACE_A0(reg), A0; \
  MOV offset+PTRACE_A1(reg), A1; \
  MOV offset+PTRACE_A2(reg), A2; \
  MOV offset+PTRACE_A3(reg), A3; \
  MOV offset+PTRACE_A4(reg), A4; \
  MOV offset+PTRACE_A5(reg), A5; \
  MOV offset+PTRACE_A6(reg), A6; \
  MOV offset+PTRACE_A7(reg), A7; \
  MOV offset+PTRACE_S2(reg), S2; \
  MOV offset+PTRACE_S3(reg), S3; \
  MOV offset+PTRACE_S4(reg), S4; \
  MOV offset+PTRACE_S5(reg), S5; \
  MOV offset+PTRACE_S6(reg), S6; \
  MOV offset+PTRACE_S7(reg), S7; \
  MOV offset+PTRACE_S8(reg), S8; \
  MOV offset+PTRACE_S9(reg), S9; \
  MOV offset+PTRACE_S10(reg), S10; \
  MOV offset+PTRACE_S11(reg), g; \
  MOV offset+PTRACE_T3(reg), T3; \
  MOV offset+PTRACE_T4(reg), T4; \
  MOV offset+PTRACE_T5(reg), T5; \
  MOV offset+PTRACE_T6(reg), T6; 

TEXT ·start(SB),NOSPLIT,$0
	JMP	·kernelExitToSupervisor(SB)

// func AddrOfStart() uintptr
TEXT ·AddrOfStart(SB), $0-8
	MOV	$·start(SB), A0
	MOV	A0, ret+0(FP)
	RET

// storeAppASID writes the application's asid value.
TEXT ·storeAppASID(SB),NOSPLIT,$0-8
	MOV asid+0(FP), A1
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV A1, CPU_APP_ASID(TP)
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	RET

// storeFpstate writes the address of application's fpstate.
TEXT ·storeFpState(SB),NOSPLIT,$0-8
	MOV value+0(FP), A1
	LOAD_KERNEL_ADDRESS(A1, A2)
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV A2, CPU_APP_FPSTATE(TP)
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	RET

// See kernel.go.
TEXT ·Halt(SB),NOSPLIT,$0
	// Trigger MMIO_EXIT/_KVM_HYPERCALL_VMEXIT.
	//
	// Using the same approach on ARM64, it will trigger a MMIO-EXIT by writing to
	// a read-only space
	WORD	$0x10502573 // csrr a0, stvec
	MOVW	ZERO, (A0)
	RET

TEXT ·kernelExitToSupervisor(SB),NOSPLIT,$0
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV	CPU_REGISTERS+PTRACE_PC(TP), A1
	WORD	$0x14159073 // csrw sepc, a1
	WORD	$0x100025f3 // csrr a1, sstatus
	ORI	$0x100, A1 // set SPP=1
	MOV	$0x20, A2
	NOT	A2
	AND	A2, A1 // set SPIE=0
	ORI     $0x6000, A1 // set fs
	WORD	$0x10059073 // csrw sstatus, a1

	MOV	CPU_SATP_KVM(TP), A1
	WORD	$0x18059073 // csrw satp, a1	

	// Save floating point state. CPU.floatingPointState is a slice, so the
	// first word of CPU.floatingPointState is a pointer to the destination
	// array.
	MOV	CPU_FPSTATE(TP), A1
	FPREGS_LOAD(A1)
	REGISTERS_LOAD(TP, CPU_REGISTERS)

	// load sentry's tls
	MOV	CPU_REGISTERS+PTRACE_TP(TP), TP
	SRET

TEXT ·kernelExitToUser(SB),NOSPLIT,$0
	// Step1, save sentry context into memory.
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	REGISTERS_SAVE(TP, CPU_REGISTERS)
	MOV	RA, CPU_REGISTERS+PTRACE_PC(TP)
	MOV	TP, T0
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV	TP, CPU_REGISTERS+PTRACE_TP(T0)
	MOV	T0, TP

	// Step2, switch to temporary stack.
	LOAD_KERNEL_STACK

	// switch to kernel space addr to execute codes below
	LUI	$-0x80000, T0
	SLLI	$0x10, T0
	MOV	$·doKernelExitToUser(SB), T1
	OR	T0, T1, T1
	JMP	(T1)

TEXT ·doKernelExitToUser(SB),NOSPLIT,$0
	// switch to user pagetable
	MOV	CPU_SATP_APP(TP), A1
	MOV	CPU_APP_ASID(TP), A2
	SLLI	$44, A2, A3
	OR	A3, A1, A1
	WORD	$0x18059073 // csrw satp, a1	

	// load app context pointer.
	MOV	CPU_APP_ADDR(TP), T0
	
	// prepare the environment for container application.
	// set pc
	MOV	PTRACE_PC(T0), A1
	WORD	$0x14159073 // csrw sepc, a1
	// set sstatus
	WORD	$0x100025f3 // csrr a1, sstatus
	MOV	$0x100, A2
	NOT	A2, A2
	AND	A1, A2, A1 // set SPP=0
	ORI	$0x20, A1 // set SPIE=1
	ORI     $0x6000, A1 // set fs
	WORD	$0x10059073 // csrw sstatus, a1
	MOV	CPU_APP_FPSTATE(TP), T1
	FPREGS_LOAD(T1)
	REGISTERS_LOAD_EXCEPT_T0(T0, 0)
	// set tp
	MOV	PTRACE_TP(T0), TP
	MOV	PTRACE_T0(T0), T0

	SRET

TEXT ·HaltEcallAndResume(SB),NOSPLIT,$0
	MOV	CPU_SELF(TP), T0
	MOV	T0, 8(SP)
	
	CALL	·kernelSyscall(SB)
	JMP	·kernelExitToSupervisor(SB)

TEXT ·HaltExceptionAndResume(SB),NOSPLIT,$0
	MOV	CPU_SELF(TP), T1    // Load vCPU
	MOV	T1, 8(SP)           // First argument (VCPU)
	MOV	T0, 16(SP)          // Second argument (vector)
	CALL	·kernelException(SB)   // Call the trampoline.
	JMP	·kernelExitToSupervisor(SB)      // Resume.

// vectors implements exception vector table.
TEXT ·vectors(SB),NOSPLIT,$0
	PCALIGN $4
	MOV	ZERO, ZERO
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV	T0, CPU_STACK_TOP-8(TP)
	WORD	$0x100022f3 // csrr t0, sstatus
	ANDI	$0x100, T0
	BNE	T0, ZERO, entry_from_supervisor
entry_from_user:
	MOV	CPU_APP_ADDR(TP), T0
	REGISTERS_SAVE_EXCEPT_T0(T0, 0)
	MOV	CPU_APP_FPSTATE(TP), T1
	FPREGS_SAVE(T1)
	MOV	TP, T1
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV	TP, PTRACE_TP(T0)
	MOV	T1, TP
	WORD	$0x14102373 // csrr t1, sepc
	MOV	T1, PTRACE_PC(T0)
	WORD	$0x10002373 // csrr t1, sstatus
	MOV	CPU_STACK_TOP-8(TP), T1
	MOV	T1, PTRACE_T0(T0)
	LOAD_KERNEL_STACK

	WORD	$0x14202373 // csrr t1, scause
	BLT	T1, ZERO, interrupts_user
exceptions_user:
	// use 32 exception codes for now
	ANDI	$0xff, T1
	MOV	$0x8, T2
	BEQ	T1, T2, handle_user_ecall
	MOV	$0x2, T2
	BEQ	T1, T2, illegal_instruction_fault	

	MOV	T1, CPU_VECTOR_CODE(TP)
	MOV	T1, CPU_ERROR_CODE(TP)
	MOV	$1, T1
	MOV	T1, CPU_ERROR_TYPE(TP)
	WORD	$0x14302373 // csrr t1, stval
	MOV	T1, CPU_FAULT_ADDR(TP)
	JMP	·kernelExitToSupervisor(SB)

illegal_instruction_fault:
	MOV	T1, CPU_VECTOR_CODE(TP)
	MOV	T1, CPU_ERROR_CODE(TP)
	MOV	$1, T1
	MOV	T1, CPU_ERROR_TYPE(TP)
	WORD	$0x14102373 // csrr t1, sepc
	MOV	T1, CPU_FAULT_ADDR(TP)
	JMP	·kernelExitToSupervisor(SB)

interrupts_user:
	MOV	$0x9, T2
	AND	T1, T2, T3
	BEQ	T2, T3, virtualization_exception
	MOV	$0x19, T2
	AND 	T1, T2, T3
	BEQ	T2, T3, exceptions_user
	MOV	$0x1a, T2
	AND	T1, T2, T3
	BEQ	T2, T3, sigbus
	JMP	virtualization_exception

sigbus:
	MOV	T2, CPU_ERROR_CODE(TP)
	MOV	$1, T1
	MOV	T1, CPU_ERROR_TYPE(TP)
	WORD	$0x14102373 // csrr t1, sepc
	MOV	T1, CPU_FAULT_ADDR(TP)
	JMP	·kernelExitToSupervisor(SB)
	

virtualization_exception:
	MOV	T3, CPU_VECTOR_CODE(TP)
	MOV	ZERO, CPU_ERROR_CODE(TP)
	MOV	$1, T1
	MOV	T1, CPU_ERROR_TYPE(TP)
	JMP	·kernelExitToSupervisor(SB)

handle_user_ecall:
	MOV	T1, CPU_VECTOR_CODE(TP)
	MOV	ZERO, CPU_ERROR_CODE(TP) // Clear error code
	MOV	$1, T1
	MOV	T1, CPU_ERROR_TYPE(TP) // Set error type to user
	// when return, executing next instruction
	MOV	PTRACE_PC(T0), T1
	ADDI	$4, T1
	MOV	T1, PTRACE_PC(T0)
	JMP	·kernelExitToSupervisor(SB)

entry_from_supervisor:
	MOV CPU_STACK_TOP-8(TP), T0
	REGISTERS_SAVE(TP, CPU_REGISTERS)
	// Save floating point state. CPU.floatingPointState is a slice, so the
	// first word of CPU.floatingPointState is a pointer to the destination
	// array.
	MOV	CPU_FPSTATE(TP), T1
	FPREGS_SAVE(T1)

	MOV	TP, T0
	WORD	$0x14021273 // csrrw tp, sscratch, tp
	MOV	TP, CPU_REGISTERS+PTRACE_TP(T0)
	MOV	T0, TP
	WORD	$0x141022f3 // csrr t0, sepc
	MOV	T0, CPU_REGISTERS+PTRACE_PC(TP)
	LOAD_KERNEL_STACK
	WORD	$0x142022f3 // csrr t0, scause
	BLT	T0, ZERO, interrupts
exceptions:
	// Ecall from HS-Mode / S-Mode
	MOV	$0x9, T1
	BEQ	T1, T0, handle_supervisor_ecall
	// Ecall from VS-Mode
	MOV	$0xa, T1
	BEQ	T1, T0, handle_supervisor_ecall
	JMP	·HaltExceptionAndResume(SB)
interrupts:
	JMP	end

handle_supervisor_ecall:
	JMP	·HaltEcallAndResume(SB)
end:	
	JMP	·kernelExitToSupervisor(SB)
	SRET

// func AddrOfVectors() uintptr
TEXT ·AddrOfVectors(SB), $0-8
	MOV    $·vectors(SB), A0
	MOV    A0, ret+0(FP)
	RET
