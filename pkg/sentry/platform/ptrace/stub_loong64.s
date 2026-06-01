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

#include "funcdata.h"
#include "textflag.h"

// LoongArch uses the asm-generic syscall table.
#define SYS_GETPID    172
#define SYS_EXIT      93
#define SYS_KILL      129
#define SYS_GETPPID   173
#define SYS_PRCTL     167

#define SIGKILL       9
#define SIGSTOP       19

#define PR_SET_PDEATHSIG 1

// stub bootstraps a freshly cloned child and SIGSTOPs itself for the
// tracer to attach. Register usage (mirrors the arm64 stub):
//
//   $a7 = R11           : syscall number (clobbered every iteration)
//   $a0..$a5 = R4..R9   : syscall args; $a0 also carries the return value
//   $s0 = R23           : expected PPID, set by initChildProcessPPID
//   $s1 = R24           : 1 on the initial bootstrap; 1 again when the
//                         sentry wants the next stop to be a clone return
//
// The callee-saved $s0 / $s1 survive every syscall the kernel performs on
// our behalf, so they hold the long-lived state.
TEXT ·stub(SB),NOSPLIT,$0
begin:
	// prctl(PR_SET_PDEATHSIG, SIGKILL) — die if our parent dies.
	MOVV	$SYS_PRCTL, R11
	MOVV	$PR_SET_PDEATHSIG, R4
	MOVV	$SIGKILL, R5
	SYSCALL

	// If $a0 < 0 (errno) bail out.
	BLT	R4, R0, error

	// getppid() — verify expected PPID.
	MOVV	$SYS_GETPPID, R11
	SYSCALL
	BNE	R4, R23, parent_dead

	// getpid() — needed to address ourselves in the upcoming kill().
	MOVV	$SYS_GETPID, R11
	SYSCALL
	BLT	R4, R0, error

	// $s1 := 0 — default "this stop is a fresh attach, not a clone
	// return". The sentry may rewrite $s1 = 1 between stops to signal
	// "you just returned from a clone".
	MOVV	$0, R24

	// kill(self, SIGSTOP) — $a0 still holds our pid.
	MOVV	$SYS_KILL, R11
	MOVV	$SIGSTOP, R5
	SYSCALL

	// After resume, examine $s1.
	MOVV	$1, R12
	BEQ	R24, R12, clone

done:
	// Notify the sentry that the stub is idle and ready for syscall
	// injection. BREAK code 3 is the agreed rendezvous (matches arm64
	// BRK $3).
	BREAK	$3
	JMP	done

clone:
	// A clone() was injected and just returned. $a0 == 0 in the child,
	// non-zero in the parent. The child re-runs the bootstrap so it
	// sees a fresh expected-PPID, etc.
	BEQ	R4, R0, begin
	JMP	done

error:
	// Generic failure path: exit(1). We deliberately do not surface the
	// real errno; this only fires if prctl / getpid themselves fail,
	// which on a sane kernel never happens.
	MOVV	$1, R4
	MOVV	$SYS_EXIT, R11
	SYSCALL
	BREAK	$0

parent_dead:
	// Expected PPID mismatch — the sentry is gone. exit(1).
	MOVV	$SYS_EXIT, R11
	MOVV	$1, R4
	SYSCALL
	BREAK	$0

// func addrOfStub() uintptr
TEXT ·addrOfStub(SB), $0-8
	MOVV	$·stub(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// stubCall jumps to the stub at the given address, after seeding the
// expected PPID into $s0. Used when the stub blob is mmap'd at an
// arbitrary location and called directly (no ptrace involvement on entry).
//
// func stubCall(addr uintptr, pid int32)
TEXT ·stubCall(SB),NOSPLIT,$0-16
	MOVV	addr+0(FP), R4
	MOVV	pid+8(FP), R23
	MOVV	$1, R24       // mark this as the initial bootstrap path
	JMP	(R4)
