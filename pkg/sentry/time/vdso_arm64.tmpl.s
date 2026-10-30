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

//go:build arm64

#include "textflag.h"

#define SYS_clock_gettime 113

// Offsets into runtime.g, runtime.gobuf, runtime.stack, and runtime.m.
#define g_m {{ Offset (Import "runtime") "g.m" }}
#define g_sched {{ Offset (Import "runtime") "g.sched" }}
#define g_stack {{ Offset (Import "runtime") "g.stack" }}
#define gobuf_sp {{ Offset (Import "runtime") "gobuf.sp" }}
#define stack_lo {{ Offset (Import "runtime") "stack.lo" }}
#define m_curg {{ Offset (Import "runtime") "m.curg" }}
#define m_g0 {{ Offset (Import "runtime") "m.g0" }}
#define m_gsignal {{ Offset (Import "runtime") "m.gsignal" }}
#define m_vdsoPC {{ Offset (Import "runtime") "m.vdsoPC" }}
#define m_vdsoSP {{ Offset (Import "runtime") "m.vdsoSP" }}

// vdsoClockGettime calls clock_gettime via the Linux VDSO when available,
// following the Go runtime's VDSO calling convention (see runtime.walltime in
// runtime/sys_linux_arm64.s).
//
// Callee-saved registers preserved across the AAPCS64 C VDSO call:
//   R20: saved Go RSP
//   R21: *runtime.m
//   R22: m.gsignal.stack.lo (when g is saved for signal handling)
//   g (R28): *runtime.g (callee-saved in AAPCS64, so valid after BL returns,
//            though C code may transiently spill/reuse R28 while inside VDSO)
//
// Local frame layout ($16-24):
//   0(RSP):  reserved link register slot
//   8(RSP):  saved m.vdsoPC
//   16(RSP): saved m.vdsoSP
//
// func vdsoClockGettime(clockid ClockID, ts *unix.Timespec) int
TEXT ·vdsoClockGettime(SB), NOSPLIT, $16-24
	// 1. Load C ABI / syscall arguments (R0 = clockid, R1 = ts) and fall
	// back to the clock_gettime syscall if no VDSO symbol is available.
	MOVW	clockid+0(FP), R0
	MOVD	ts+8(FP), R1
	MOVD	runtime·vdsoClockgettimeSym(SB), R2
	CBZ	R2, fallback

	// 2. Save Go RSP and load m = g.m.
	MOVD	RSP, R20
	MOVD	RSP, R3
	MOVD	g_m(g), R21

	// 3. Record caller PC/SP in m.vdsoPC/m.vdsoSP for SIGPROF tracebacks.
	// Save previous values on the local frame so this function is reentrant
	// if invoked again from a signal handler.
	MOVD	m_vdsoPC(R21), R4
	MOVD	m_vdsoSP(R21), R5
	MOVD	R4, 8(RSP)
	MOVD	R5, 16(RSP)

	MOVD	$clockid-8(FP), R4	// Caller's RSP.
	MOVD	LR, m_vdsoPC(R21)
	MOVD	R4, m_vdsoSP(R21)

	// 4. Switch to m.g0's stack when running on a user goroutine (m.curg),
	// since C VDSO code may use more stack than Go's NOSPLIT redzone.
	// Stay on the current stack if already on g0 or gsignal.
	MOVD	m_curg(R21), R4
	CMP	g, R4
	BNE	noswitch
	MOVD	m_g0(R21), R4
	MOVD	(g_sched+gobuf_sp)(R4), R3

noswitch:
	// Reserve 16 bytes below R3 so C code cannot clobber the caller frame
	// pointer saved by Go's arm64 prologue at -8(R3), and align RSP to 16
	// bytes as required by AAPCS64.
	SUB	$16, R3
	BIC	$15, R3
	MOVD	R3, RSP

	// 5. Save g at m.gsignal.stack.lo so runtime.sigFetchG can recover g if
	// a signal arrives while executing VDSO C code (where R28 may hold an
	// arbitrary C value). Skip when cgo is enabled (g is in TLS), when
	// m.gsignal is nil, or when already running on m.gsignal.
	MOVBU	runtime·iscgo(SB), R22
	CBNZ	R22, nosaveg
	MOVD	m_gsignal(R21), R22
	CBZ	R22, nosaveg
	CMP	g, R22
	BEQ	nosaveg
	MOVD	(g_stack+stack_lo)(R22), R22
	MOVD	g, (R22)

	BL	(R2)

	MOVD	ZR, (R22)		// Clear saved g slot on gsignal stack.
	B	finish

nosaveg:
	BL	(R2)

finish:
	// 6. Sign-extend the 32-bit C int return value and restore Go RSP and
	// previous m.vdsoSP/m.vdsoPC.
	MOVW	R0, R0
	MOVD	R20, RSP
	MOVD	16(RSP), R4
	MOVD	R4, m_vdsoSP(R21)
	MOVD	8(RSP), R4
	MOVD	R4, m_vdsoPC(R21)
	MOVD	R0, ret+16(FP)
	RET

fallback:
	MOVD	$SYS_clock_gettime, R8
	SVC
	MOVD	R0, ret+16(FP)
	RET
