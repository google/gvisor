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

#include "textflag.h"

#define SIGBUS  7
#define SIGSEGV 11

// LoongArch glibc ucontext_t layout (sysdeps/unix/sysv/linux/loongarch):
//
//   offset 0   : uc_flags        (u64)
//   offset 8   : uc_link         (ptr)
//   offset 16  : uc_stack        (24 bytes)
//   offset 40  : uc_sigmask      (128 bytes, glibc 1024-bit sigset_t)
//   offset 168 : pad to 16-byte alignment (8 bytes)
//   offset 176 : uc_mcontext / struct sigcontext { u64 sc_pc; u64 sc_regs[32]; u32 sc_flags; ... }
//
// Hence:
#define REG_PC 0xB0                 // mcontext base + 0
#define REG_A0 0xD8                 // mcontext base + 8 + 4*8  (sc_regs[4])
#define REG_A1 0xE0                 // mcontext base + 8 + 5*8  (sc_regs[5])

// siginfo_t (asm-generic):
//   0  : si_signo
//   4  : si_errno
//   8  : si_code
//   16 : si_addr (for SIGSEGV / SIGBUS)
#define SI_CODE 0x08
#define SI_ADDR 0x10

// signalHandler is the SIGSEGV / SIGBUS handler installed by safecopy's
// init(). The kernel invokes it via rt_sigaction with the LoongArch
// signal-handler ABI:
//
//   R4 = signo
//   R5 = siginfo_t*
//   R6 = ucontext_t*
//
// If the interrupted PC sits inside one of the registered safecopy
// functions, we rewrite ucontext.sc_pc to point at the function's
// handle*Fault stub and set ucontext.sc_regs[4] = fault address,
// ucontext.sc_regs[5] = signal number. Otherwise we tail-call the
// previously installed handler (typically the Go runtime's).
TEXT ·signalHandler(SB), NOSPLIT, $0
	// si_code > 0 means kernel-generated signal (faulting access).
	// Anything else (raise(), tgkill(), ...) is delegated.
	MOVW	SI_CODE(R5), R7
	BGE	R0, R7, original_handler

	MOVV	REG_PC(R6), R7

	MOVV	·memcpyBegin(SB), R8
	BLTU	R7, R8, not_memcpy
	MOVV	·memcpyEnd(SB), R8
	BGEU	R7, R8, not_memcpy
	MOVV	$handleMemcpyFault(SB), R7
	JMP	handle_fault

not_memcpy:
	MOVV	·memclrBegin(SB), R8
	BLTU	R7, R8, not_memclr
	MOVV	·memclrEnd(SB), R8
	BGEU	R7, R8, not_memclr
	MOVV	$handleMemclrFault(SB), R7
	JMP	handle_fault

not_memclr:
	MOVV	·swapUint32Begin(SB), R8
	BLTU	R7, R8, not_swap32
	MOVV	·swapUint32End(SB), R8
	BGEU	R7, R8, not_swap32
	MOVV	$handleSwapUint32Fault(SB), R7
	JMP	handle_fault

not_swap32:
	MOVV	·swapUint64Begin(SB), R8
	BLTU	R7, R8, not_swap64
	MOVV	·swapUint64End(SB), R8
	BGEU	R7, R8, not_swap64
	MOVV	$handleSwapUint64Fault(SB), R7
	JMP	handle_fault

not_swap64:
	MOVV	·compareAndSwapUint32Begin(SB), R8
	BLTU	R7, R8, not_cas32
	MOVV	·compareAndSwapUint32End(SB), R8
	BGEU	R7, R8, not_cas32
	MOVV	$handleCompareAndSwapUint32Fault(SB), R7
	JMP	handle_fault

not_cas32:
	MOVV	·loadUint32Begin(SB), R8
	BLTU	R7, R8, original_handler
	MOVV	·loadUint32End(SB), R8
	BGEU	R7, R8, original_handler
	MOVV	$handleLoadUint32Fault(SB), R7
	JMP	handle_fault

original_handler:
	// Tail-call the previously installed handler. SIGSEGV => savedSigSegVHandler,
	// SIGBUS / anything else => savedSigBusHandler.
	MOVV	·savedSigSegVHandler(SB), R8
	MOVV	·savedSigBusHandler(SB), R9
	MOVW	$SIGSEGV, R10
	BEQ	R4, R10, orig_segv
	MOVV	R9, R7
	JMP	(R7)
orig_segv:
	JMP	(R8)

handle_fault:
	// Overwrite sc_pc so the syscall stub runs after sigreturn.
	MOVV	R7, REG_PC(R6)

	// sc_regs[4] (= return a0) := fault address.
	MOVV	SI_ADDR(R5), R7
	MOVV	R7, REG_A0(R6)

	// sc_regs[5] (= return a1) := signal number.
	MOVW	R4, REG_A1(R6)

	RET

// func addrOfSignalHandler() uintptr
TEXT ·addrOfSignalHandler(SB), $0-8
	MOVV	$·signalHandler(SB), R4
	MOVV	R4, ret+0(FP)
	RET
