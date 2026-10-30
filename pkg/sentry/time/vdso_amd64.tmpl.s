// Copyright 2021 The gVisor Authors.
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

//go:build amd64

#include "textflag.h"

#define SYS_clock_gettime 228

// Offsets into runtime.g, runtime.gobuf, and runtime.m.
#define g_m {{ Offset (Import "runtime") "g.m" }}
#define g_sched {{ Offset (Import "runtime") "g.sched" }}
#define gobuf_sp {{ Offset (Import "runtime") "gobuf.sp" }}
#define m_curg {{ Offset (Import "runtime") "m.curg" }}
#define m_g0 {{ Offset (Import "runtime") "m.g0" }}
#define m_vdsoPC {{ Offset (Import "runtime") "m.vdsoPC" }}
#define m_vdsoSP {{ Offset (Import "runtime") "m.vdsoSP" }}

// vdsoClockGettime calls clock_gettime via the Linux VDSO when available,
// following the Go runtime's VDSO calling convention (see runtime.nanotime1 in
// runtime/sys_linux_amd64.s).
//
// Callee-saved registers preserved across the System V AMD64 C VDSO call:
//   R12: saved Go SP
//   BX:  *runtime.m
//
// Local frame layout ($16-24):
//   0(SP): saved m.vdsoPC
//   8(SP): saved m.vdsoSP
//
// On amd64, runtime.sigFetchG always loads g from TLS (%fs), so g does not
// need to be saved to m.gsignal.stack.lo before entering the VDSO.
//
// func vdsoClockGettime(clockid ClockID, ts *unix.Timespec) int
TEXT ·vdsoClockGettime(SB), NOSPLIT, $16-24
	// 1. Load C ABI / syscall arguments (DI = clockid, SI = ts) and fall
	// back to the clock_gettime syscall if no VDSO symbol is available.
	MOVL	clockid+0(FP), DI
	MOVQ	ts+8(FP), SI
	MOVQ	runtime·vdsoClockgettimeSym(SB), AX
	CMPQ	AX, $0
	JEQ	fallback

	// 2. Save Go SP and load g (from TLS on ABI0 entry) and m = g.m.
	MOVQ	SP, R12
	MOVQ	(TLS), R14
	MOVQ	g_m(R14), BX

	// 3. Record caller PC/SP in m.vdsoPC/m.vdsoSP for SIGPROF tracebacks.
	// Save previous values on the local frame so this function is reentrant
	// if invoked again from a signal handler.
	MOVQ	m_vdsoPC(BX), CX
	MOVQ	m_vdsoSP(BX), DX
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)

	LEAQ	clockid+0(FP), DX	// Caller's SP (above return PC).
	MOVQ	-8(DX), CX		// Caller's return PC.
	MOVQ	CX, m_vdsoPC(BX)
	MOVQ	DX, m_vdsoSP(BX)

	// 4. Switch to m.g0's stack when running on a user goroutine (m.curg),
	// since C VDSO code may use more stack than Go's NOSPLIT redzone.
	// Stay on the current stack if already on g0 or gsignal.
	CMPQ	R14, m_curg(BX)
	JNE	noswitch
	MOVQ	m_g0(BX), DX
	MOVQ	(g_sched+gobuf_sp)(DX), SP

noswitch:
	// 5. Align SP to 16 bytes as required by the System V AMD64 ABI before
	// CALL, invoke the VDSO function, and sign-extend its 32-bit C int
	// return value.
	ANDQ	$~15, SP
	CALL	AX
	MOVLQSX	AX, AX

	// 6. Restore Go SP and previous m.vdsoSP/m.vdsoPC.
	MOVQ	R12, SP
	MOVQ	8(SP), CX
	MOVQ	CX, m_vdsoSP(BX)
	MOVQ	0(SP), CX
	MOVQ	CX, m_vdsoPC(BX)
	MOVQ	AX, ret+16(FP)
	RET

fallback:
	MOVQ	$SYS_clock_gettime, AX
	SYSCALL
	MOVQ	AX, ret+16(FP)
	RET
