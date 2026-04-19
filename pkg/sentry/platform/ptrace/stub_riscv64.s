// Copyright 2019 The gVisor Authors.
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

#define SYS_GETPID		172
#define SYS_EXIT		93
#define SYS_KILL		129
#define SYS_GETPPID		173
#define SYS_PRCTL		167

#define SIGKILL			9
#define SIGSTOP			19

#define PR_SET_PDEATHSIG	1

// stub bootstraps the child and sends itself SIGSTOP to wait for attach.
//
// R7 contains the expected PPID.
//
// This should not be used outside the context of a new ptrace child (as the
// function is otherwise a bunch of nonsense).
TEXT ·stub(SB),NOSPLIT,$0
begin:
	// N.B. This loop only executes in the context of a single-threaded
	// fork child.

	MOV $SYS_PRCTL, A7
	MOV $PR_SET_PDEATHSIG, A0
	MOV $SIGKILL, A1
	ECALL

	BNE ZERO, A0, error

	// If the parent already died before we called PR_SET_DEATHSIG then
	// we'll have an unexpected PPID.
	MOV $SYS_GETPPID, A7
	ECALL

	BNE A0, S7, parent_dead

	MOV $SYS_GETPID, A7
	ECALL

	BLT A0, ZERO, error

	MOV ZERO, S8

	// SIGSTOP to wait for attach.
	//
	// The SYSCALL instruction will be used for future syscall injection by
	// thread.syscall.
	MOV $SYS_KILL, A7
	MOV $SIGSTOP, A1
	ECALL

	// The sentry sets S8 to 1 when creating stub process.
	MOV $1, T1
	BEQ T1, S8, clone

done:
	// Notify the Sentry that syscall exited.
	EBREAK
	JMP done // Be paranoid
clone:
	// subprocess.createStub clones a new stub process that is untraced,
	// thus executing this code. We setup the PDEATHSIG before SIGSTOPing
	// ourselves for attach by the tracer.
	//
	// S7 has been updated with the expected PPID.
	BEQ ZERO, A0, begin

	// The clone system call returned a non-zero value.
	JMP done

error:
	// Exit with -errno.
	NEG A0, A0
	MOV $SYS_EXIT, A7
	ECALL
	WORD $0x10500073 // WFI

parent_dead:
	MOV $SYS_EXIT, A7
	MOV $1, A0
	ECALL
	WORD $0x10500073 // WFI

// func addrOfStub() uintptr
TEXT ·addrOfStub(SB), $0-8
	MOV	$·stub(SB), A0
	MOV	A0, ret+0(FP)
	RET

// stubCall calls the stub function at the given address with the given PPID.
//
// This is a distinct function because stub, above, may be mapped at any
// arbitrary location, and stub has a specific binary API (see above).
TEXT ·stubCall(SB),NOSPLIT,$0-16
	MOV addr+0(FP), A0
	MOV pid+8(FP), S7
	JMP (A0)
