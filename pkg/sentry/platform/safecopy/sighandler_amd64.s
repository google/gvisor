// Copyright 2018 Google Inc.
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

#include "textflag.h"

// The signals handled by sigHandler.
#define SIGBUS  7
#define SIGSEGV 11

// Offsets to the registers in context->uc_mcontext.gregs[].
#define REG_RDI 0x68
#define REG_RAX 0x90
#define REG_IP  0xa8

// Offset to the si_addr field of siginfo.
#define SI_CODE 0x08
#define SI_ADDR 0x10

// signalHandler is the signal handler for SIGSEGV and SIGBUS signals. It must
// not be set up as a handler to any other signals.
//
// If the instruction causing the signal is within a safecopy-protected
// function, the signal is handled such that execution resumes in the
// appropriate fault handling stub with AX containing the faulting address and
// DI containing the signal number. Otherwise control is transferred to the
// previously configured signal handler (savedSigSegvHandler or
// savedSigBusHandler).
//
// This function cannot be written in go because it runs whenever a signal is
// received by the thread (preempting whatever was running), which includes when
// garbage collector has stopped or isn't expecting any interactions (like
// barriers).
//
// The arguments are the following:
// DI - The signal number.
// SI - Pointer to siginfo_t structure.
// DX - Pointer to ucontext structure.
TEXT ·signalHandler(SB),NOSPLIT,$0
	// Check if the signal is from the kernel.
	MOVQ $0x0, CX
	CMPL CX, SI_CODE(SI)
	JGE original_handler

	// Check if RIP is within the area we care about.
	MOVQ REG_IP(DX), CX
	CMPQ CX, ·memcpyBegin(SB)
	JB not_memcpy
	CMPQ CX, ·memcpyEnd(SB)
	JAE not_memcpy

	// Modify the context such that execution will resume in the fault
	// handler.
	LEAQ handleMemcpyFault(SB), CX
	JMP handle_fault

not_memcpy:
	CMPQ CX, ·memclrBegin(SB)
	JB not_memclr
	CMPQ CX, ·memclrEnd(SB)
	JAE not_memclr

	LEAQ handleMemclrFault(SB), CX
	JMP handle_fault

not_memclr:
	CMPQ CX, ·swapUint32Begin(SB)
	JB not_swapuint32
	CMPQ CX, ·swapUint32End(SB)
	JAE not_swapuint32

	LEAQ handleSwapUint32Fault(SB), CX
	JMP handle_fault

not_swapuint32:
	CMPQ CX, ·swapUint64Begin(SB)
	JB not_swapuint64
	CMPQ CX, ·swapUint64End(SB)
	JAE not_swapuint64

	LEAQ handleSwapUint64Fault(SB), CX
	JMP handle_fault

not_swapuint64:
	CMPQ CX, ·compareAndSwapUint32Begin(SB)
	JB not_casuint32
	CMPQ CX, ·compareAndSwapUint32End(SB)
	JAE not_casuint32

	LEAQ handleCompareAndSwapUint32Fault(SB), CX
	JMP handle_fault

not_casuint32:
original_handler:
	// Jump to the previous signal handler, which is likely the golang one.
	XORQ CX, CX
	MOVQ ·savedSigBusHandler(SB), AX
	CMPL DI, $SIGSEGV
	CMOVQEQ ·savedSigSegVHandler(SB), AX
	JMP AX

handle_fault:
	// Entered with the address of the fault handler in RCX; store it in
	// RIP.
	MOVQ CX, REG_IP(DX)

	// Store the faulting address in RAX.
	MOVQ SI_ADDR(SI), CX
	MOVQ CX, REG_RAX(DX)

	// Store the signal number in EDI.
	MOVL DI, REG_RDI(DX)

	RET
