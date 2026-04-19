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

#include "textflag.h"

// The signals handled by sigHandler.
#define SIGBUS 7
#define SIGSEGV 11

// Offsets to the registers in context->uc_mcontext.gregs[].
#define REG_A0 0x100
#define REG_A1 0x108
#define REG_PC 0xB0

// Offset to the si_addr field of siginfo.
#define SI_CODE 0x08
#define SI_ADDR 0x10

// signalHandler is the signal handler for SIGSEGV and SIGBUS signals. It must
// not be set up as a handler to any other signals.
//
// If the instruction causing the signal is within a safecopy-protected
// function, the signal is handled such that execution resumes in the
// appropriate fault handling stub with A0 containing the faulting address and
// A1 containing the signal number. Otherwise control is transferred to the
// previously configured signal handler (savedSigSegvHandler or
// savedSigBusHandler).
//
// This function cannot be written in go because it runs whenever a signal is
// received by the thread (preempting whatever was running), which includes when
// garbage collector has stopped or isn't expecting any interactions (like
// barriers).
//
// The arguments are the following:
// A0 - The signal number.
// A1 - Pointer to siginfo_t structure.
// A2 - Pointer to ucontext structure.
TEXT ·signalHandler(SB),NOSPLIT,$0
	// Check if the signal is from the kernel, si_code > 0 means a kernel signal.
	MOVW SI_CODE(A1), A7
	BLE A7, ZERO, original_handler

	// Check if PC is within the area we care about.
	MOV REG_PC(A2), A7
	MOV ·memcpyBegin(SB), A6
	BLT A7, A6, not_memcpy
	MOV ·memcpyEnd(SB), A6
	BGE A7, A6, not_memcpy

	// Modify the context such that execution will resume in the fault handler.
	MOV $handleMemcpyFault(SB), A7
	JMP handle_fault

not_memcpy:
	MOV ·memclrBegin(SB), A6
	BLT A7, A6, not_memclr
	MOV ·memclrEnd(SB), A6
	BGE A7, A6, not_memclr

	MOV $handleMemclrFault(SB), A7
	JMP handle_fault

not_memclr:
	MOV ·swapUint32Begin(SB), A6
	BLT A7, A6, not_swapuint32
	MOV ·swapUint32End(SB), A6
	BGE A7, A6, not_swapuint32

	MOV $handleSwapUint32Fault(SB), A7
	JMP handle_fault

not_swapuint32:
	MOV ·swapUint64Begin(SB), A6
	BLT A7, A6, not_swapuint64
	MOV ·swapUint64End(SB), A6
	BGE A7, A6, not_swapuint64

	MOV $handleSwapUint64Fault(SB), A7
	JMP handle_fault

not_swapuint64:
	MOV ·compareAndSwapUint32Begin(SB), A6
	BLT A7, A6, not_casuint32
	MOV ·compareAndSwapUint32End(SB), A6
	BGE A7, A6, not_casuint32

	MOV $handleCompareAndSwapUint32Fault(SB), A7
	JMP handle_fault

not_casuint32:
	MOV ·loadUint32Begin(SB), A6
	BLT A7, A6, not_loaduint32
	MOV ·loadUint32End(SB), A6
	BGE A7, A6, not_loaduint32

	MOV $handleLoadUint32Fault(SB), A7
	JMP handle_fault

not_loaduint32:
original_handler:
	// Jump to the previous signal handler, which is likely the golang one.
	MOV ·savedSigBusHandler(SB), A7
	MOV ·savedSigSegVHandler(SB), A6
	MOV $SIGSEGV, A3
	BEQ A3, A0, is_sigsegv
	JMP (A7)
is_sigsegv:
	MOV A6, A7
	JMP (A7)

handle_fault:
	// Entered with the address of the fault handler in A7; store it in PC.
	MOV A7, REG_PC(A2)

	// Store the faulting address in A0.
	MOV SI_ADDR(A1), A7
	MOV A7, REG_A0(A2)

	// Store the signal number in A1.
	MOVW A0, REG_A1(A2)

	RET

// func addrOfSignalHandler() uintptr
TEXT ·addrOfSignalHandler(SB), $0-8
	MOV	$·signalHandler(SB), A0
	MOV	A0, ret+0(FP)
	RET
