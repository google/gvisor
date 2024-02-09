// Copyright 2023 The gVisor Authors.
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

// handleCheckXstateFault returns (the value stored in AX, the value stored in DI).
// Control is transferred to it when checkXstate below receives SIGSEGV or SIGBUS,
// with the faulting address stored in AX and the signal number stored in DI.
//
// It must have the same frame configuration as memcpy so that it can undo any
// potential call frame set up by the assembler.
TEXT handleCheckXstateFault(SB), NOSPLIT|NOFRAME, $0-26
	MOVQ	AX, addr+8(FP)
	MOVL	DI, sig+16(FP)

	LDMXCSR	mxcsr+20(FP)
	BYTE $0xDB; BYTE $0xE2; // FNCLEX
	FLDCW cw+24(FP)
	RET


// ·checkXstate verifies that the specified floating point state can be loaded.
TEXT ·checkXstate(SB),NOSPLIT|NOFRAME,$0-26
	// Store 0 as the returned signal number. If we run to completion,
	// this is the value the caller will see; if a signal is received,
	// handleMemcpyFault will store a different value in this address.
	MOVL	$0, sig+16(FP)
	// MXCSR and the x87 control word are the only floating point state
	// that is callee-save and thus we must save.
	STMXCSR mxcsr+20(FP)
	FSTCW	cw+24(FP)

	MOVQ addr+0(FP), DI
	MOVL $0xffffffff, AX
	MOVL $0xffffffff, DX
	XRSTOR64 (DI)

	// Restore MXCSR and the x87 control word.
	LDMXCSR	mxcsr+20(FP)
	BYTE $0xDB; BYTE $0xE2; // FNCLEX
	FLDCW cw+24(FP)
	RET

// func addrOfCheckXstate() uintptr
TEXT ·addrOfCheckXstate(SB), $0-8
	MOVQ	$·checkXstate(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
