// Copyright 2018 Google LLC
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
#define REG_R0 0xB8
#define REG_R1 0xC0
#define REG_PC 0x1B8

// Offset to the si_addr field of siginfo.
#define SI_CODE 0x08
#define SI_ADDR 0x10

// signalHandler is the signal handler for SIGSEGV and SIGBUS signals. It must
// not be set up as a handler to any other signals.
//
// If the instruction causing the signal is within a safecopy-protected
// function, the signal is handled such that execution resumes in the
// appropriate fault handling stub with R0 containing the faulting address and
// R1 containing the signal number. Otherwise control is transferred to the
// previously configured signal handler (savedSigSegvHandler or
// savedSigBusHandler).
//
// This function cannot be written in go because it runs whenever a signal is
// received by the thread (preempting whatever was running), which includes when
// garbage collector has stopped or isn't expecting any interactions (like
// barriers).
//
// The arguments are the following:
// R0 - The signal number.
// R1 - Pointer to siginfo_t structure.
// R2 - Pointer to ucontext structure.
TEXT ·signalHandler(SB),NOSPLIT,$0
	// Check if the signal is from the kernel, si_code > 0 means a kernel signal.
	MOVD SI_CODE(R1), R7
	CMPW $0x0, R7
	BLE original_handler

	// Check if PC is within the area we care about.
	MOVD REG_PC(R2), R7
	MOVD ·memcpyBegin(SB), R8
	CMP R8, R7
	BLO not_memcpy
	MOVD ·memcpyEnd(SB), R8
	CMP R8, R7
	BHS not_memcpy

	// Modify the context such that execution will resume in the fault handler.
	MOVD $handleMemcpyFault(SB), R7
	B handle_fault

not_memcpy:
	MOVD ·memclrBegin(SB), R8
	CMP R8, R7
	BLO not_memclr
	MOVD ·memclrEnd(SB), R8
	CMP R8, R7
	BHS not_memclr

	MOVD $handleMemclrFault(SB), R7
	B handle_fault

not_memclr:
	MOVD ·swapUint32Begin(SB), R8
	CMP R8, R7
	BLO not_swapuint32
	MOVD ·swapUint32End(SB), R8
	CMP R8, R7
	BHS not_swapuint32

	MOVD $handleSwapUint32Fault(SB), R7
	B handle_fault

not_swapuint32:
	MOVD ·swapUint64Begin(SB), R8
	CMP R8, R7
	BLO not_swapuint64
	MOVD ·swapUint64End(SB), R8
	CMP R8, R7
	BHS not_swapuint64

	MOVD $handleSwapUint64Fault(SB), R7
	B handle_fault

not_swapuint64:
	MOVD ·compareAndSwapUint32Begin(SB), R8
	CMP R8, R7
	BLO not_casuint32
	MOVD ·compareAndSwapUint32End(SB), R8
	CMP R8, R7
	BHS not_casuint32

	MOVD $handleCompareAndSwapUint32Fault(SB), R7
	B handle_fault

not_casuint32:
	MOVD ·loadUint32Begin(SB), R8
	CMP R8, R7
	BLO not_loaduint32
	MOVD ·loadUint32End(SB), R8
	CMP R8, R7
	BHS not_loaduint32

	MOVD $handleLoadUint32Fault(SB), R7
	B handle_fault

not_loaduint32:
original_handler:
	// Jump to the previous signal handler, which is likely the golang one.
	MOVD ·savedSigBusHandler(SB), R7
	MOVD ·savedSigSegVHandler(SB), R8
	CMPW $SIGSEGV, R0
	CSEL EQ, R8, R7, R7
	B (R7)

handle_fault:
	// Entered with the address of the fault handler in R7; store it in PC.
	MOVD R7, REG_PC(R2)

	// Store the faulting address in R0.
	MOVD SI_ADDR(R1), R7
	MOVD R7, REG_R0(R2)

	// Store the signal number in R1.
	MOVW R0, REG_R1(R2)

	RET
