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

#include "funcdata.h"
#include "textflag.h"

#define SIGMCTX		40          // +checkoffset arch UContext64.MContext
#define SIGCTX_R8	SIGMCTX+0   // +checkoffset arch SignalContext64.R8
#define SIGCTX_R9	SIGMCTX+8   // +checkoffset arch SignalContext64.R9
#define SIGCTX_R10	SIGMCTX+16  // +checkoffset arch SignalContext64.R10
#define SIGCTX_R11	SIGMCTX+24  // +checkoffset arch SignalContext64.R11
#define SIGCTX_R12	SIGMCTX+32  // +checkoffset arch SignalContext64.R12
#define SIGCTX_R13	SIGMCTX+40  // +checkoffset arch SignalContext64.R13
#define SIGCTX_R14	SIGMCTX+48  // +checkoffset arch SignalContext64.R14
#define SIGCTX_R15	SIGMCTX+56  // +checkoffset arch SignalContext64.R15
#define SIGCTX_RDI	SIGMCTX+64  // +checkoffset arch SignalContext64.Rdi
#define SIGCTX_RSI	SIGMCTX+72  // +checkoffset arch SignalContext64.Rsi
#define SIGCTX_RBP	SIGMCTX+80  // +checkoffset arch SignalContext64.Rbp
#define SIGCTX_RBX	SIGMCTX+88  // +checkoffset arch SignalContext64.Rbx
#define SIGCTX_RDX	SIGMCTX+96  // +checkoffset arch SignalContext64.Rdx
#define SIGCTX_RAX	SIGMCTX+104 // +checkoffset arch SignalContext64.Rax
#define SIGCTX_RCX	SIGMCTX+112 // +checkoffset arch SignalContext64.Rcx
#define SIGCTX_RSP	SIGMCTX+120 // +checkoffset arch SignalContext64.Rsp
#define SIGCTX_RIP	SIGMCTX+128 // +checkoffset arch SignalContext64.Rip
#define SIGCTX_FL	SIGMCTX+136 // +checkoffset arch SignalContext64.Eflags
#define SIGCTX_CS	SIGMCTX+144 // +checkoffset arch SignalContext64.Cs
#define SIGCTX_GS	SIGMCTX+146 // +checkoffset arch SignalContext64.Gs
#define SIGCTX_FS	SIGMCTX+148 // +checkoffset arch SignalContext64.Fs
#define SIGCTX_SS	SIGMCTX+150 // +checkoffset arch SignalContext64.Ss
#define SIGCTX_ERR	SIGMCTX+152 // +checkoffset arch SignalContext64.Err
#define SIGCTX_TRAPNO	SIGMCTX+160 // +checkoffset arch SignalContext64.Trapno
#define SIGCTX_MASK	SIGMCTX+168 // +checkoffset arch SignalContext64.Oldmask
#define SIGCTX_CR2	SIGMCTX+176 // +checkoffset arch SignalContext64.Cr2
#define SIGCTX_FPSTATE	SIGMCTX+184 // +checkoffset arch SignalContext64.Fpstate

// Callee-Save: RBX, RBP, and R12-R15 are preserved across function calls.
// Caller-Save: RAX, RCX, RDX, RSI, RDI, and R8-R11 are free to be used by
// the called function and may be overwritten.
// retjmp has to be updated when the stack frame size is changed.
TEXT ·callWithSignalFrame(SB),NOSPLIT,$8-24
	MOVQ stack+0(FP), DI
	MOVQ handler+8(FP), AX
	MOVQ sigframe+16(FP), R8

	MOVQ BX, SIGCTX_RBX(R8)
	MOVQ BP, SIGCTX_RBP(R8)
	MOVQ R12, SIGCTX_R12(R8)
	MOVQ R13, SIGCTX_R13(R8)
	MOVQ R14, SIGCTX_R14(R8)
	MOVQ R15, SIGCTX_R15(R8)
	PUSHFQ
	POPQ R9
	MOVQ R9, SIGCTX_FL(R8)
	MOVQ SP, SIGCTX_RSP(R8)
	MOVQ $·retjmp(SB),R9
	MOVQ R9, SIGCTX_RIP(R8)
	MOVQ $0x33, SIGCTX_CS(R8)
	MOVQ $0x2b, SIGCTX_SS(R8)
	MOVQ DI, SP
	PUSHQ $0x0
	MOVQ SP, BP
	PUSHQ R8    // Save CPU.
	CALL AX

#define __NR_rt_sigreturn 15 // +checkconst unix SYS_RT_SIGRETURN
TEXT ·Sigreturn(SB),NOSPLIT,$0-8
	MOVQ sigframeAddr+0(FP), SP
	MOVQ $__NR_rt_sigreturn, AX
	SYSCALL

// retjmp is the return sequence from callWithSignalFrame. It is used to set
// RIP on a signal frame.
TEXT ·retjmp(SB),NOSPLIT,$0-0
	MOVQ 8(SP), BP
	ADDQ    $0x10,SP
	RET
