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

#define SIGMCTX 40
#define SIGCTX_R8  0 + SIGMCTX
#define SIGCTX_R9  8 + SIGMCTX
#define SIGCTX_R10 16 + SIGMCTX
#define SIGCTX_R11 24 + SIGMCTX
#define SIGCTX_R12 32 + SIGMCTX
#define SIGCTX_R13 40 + SIGMCTX
#define SIGCTX_R14 48 + SIGMCTX
#define SIGCTX_R15 56 + SIGMCTX
#define SIGCTX_RDI 64 + SIGMCTX
#define SIGCTX_RSI 72 + SIGMCTX
#define SIGCTX_RBP 80 + SIGMCTX
#define SIGCTX_RBX 88 + SIGMCTX
#define SIGCTX_RDX 96 + SIGMCTX
#define SIGCTX_RAX 104 + SIGMCTX
#define SIGCTX_RCX 112 + SIGMCTX
#define SIGCTX_RSP 120 + SIGMCTX
#define SIGCTX_RIP 128 + SIGMCTX
#define SIGCTX_FL  136 + SIGMCTX
#define SIGCTX_CS  144 + SIGMCTX
#define SIGCTX_GS  146 + SIGMCTX
#define SIGCTX_FS  148 + SIGMCTX
#define SIGCTX_SS  150 + SIGMCTX
#define SIGCTX_ERR     152 + SIGMCTX
#define SIGCTX_TRAPNO  160 + SIGMCTX
#define SIGCTX_MASK    168 + SIGMCTX
#define SIGCTX_CR2     176 + SIGMCTX
#define SIGCTX_FPSTATE 184 + SIGMCTX

// Callee-Save: RBX, RBP, and R12-R15 are preserved across function calls.
// Caller-Save: RAX, RCX, RDX, RSI, RDI, and R8-R11 are free to be used by
// the called function and may be overwritten.
TEXT ·callUserSignalHandler(SB),NOSPLIT,$8-40
	MOVQ stack+0(FP), DI
	MOVQ handler+8(FP), AX
	MOVQ sigframeRAX+16(FP), SI
	MOVQ sigframe+24(FP), R8

	MOVQ fpstate+32(FP), R9
	MOVQ R9, SIGCTX_FPSTATE(R8)

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
	MOVQ $·return(SB),R9
	MOVQ R9, SIGCTX_RIP(R8)
	MOVQ $0x33, SIGCTX_CS(R8)
	MOVQ $0x2b, SIGCTX_SS(R8)
	MOVQ SI, SIGCTX_RAX(R8)
	MOVQ DI, SP
	PUSHQ $0x0
	MOVQ SP, BP
	PUSHQ R8    // Save CPU.
	CALL AX

TEXT ·UserSigreturn(SB),NOSPLIT,$0-8
	MOVQ ADDR+0(FP), SP
	MOVQ $15, AX
	SYSCALL

TEXT ·return(SB),NOSPLIT,$0-0
	ADDQ    $0x8,SP
	MOVQ (SP), BP
	ADDQ    $0x8,SP
	RET
