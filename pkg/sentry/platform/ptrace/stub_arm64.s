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

	MOVD $SYS_PRCTL, R8
	MOVD $PR_SET_PDEATHSIG, R0
	MOVD $SIGKILL, R1
	SVC

	CMN $4095, R0
	BCS error

	// If the parent already died before we called PR_SET_DEATHSIG then
	// we'll have an unexpected PPID.
	MOVD $SYS_GETPPID, R8
	SVC

	CMP R0, R7
	BNE parent_dead

	MOVD $SYS_GETPID, R8
	SVC

	CMP $0x0, R0
	BLT error

	MOVD $0, R9

	// SIGSTOP to wait for attach.
	//
	// The SYSCALL instruction will be used for future syscall injection by
	// thread.syscall.
	MOVD $SYS_KILL, R8
	MOVD $SIGSTOP, R1
	SVC

	// The sentry sets R9 to 1 when creating stub process.
	CMP $1, R9
	BEQ clone

done:
	// Notify the Sentry that syscall exited.
	BRK $3
	B done // Be paranoid.
clone:
	// subprocess.createStub clones a new stub process that is untraced,
	// thus executing this code. We setup the PDEATHSIG before SIGSTOPing
	// ourselves for attach by the tracer.
	//
	// R7 has been updated with the expected PPID.
	CMP $0, R0
	BEQ begin

	// The clone system call returned a non-zero value.
	B done

error:
	// Exit with -errno.
	NEG R0, R0
	MOVD $SYS_EXIT, R8
	SVC
	HLT

parent_dead:
	MOVD $SYS_EXIT, R8
	MOVD $1, R0
	SVC
	HLT

// func addrOfStub() uintptr
TEXT ·addrOfStub(SB), $0-8
	MOVD	$·stub(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// stubCall calls the stub function at the given address with the given PPID.
//
// This is a distinct function because stub, above, may be mapped at any
// arbitrary location, and stub has a specific binary API (see above).
TEXT ·stubCall(SB),NOSPLIT,$0-16
	MOVD addr+0(FP), R0
	MOVD pid+8(FP), R7
	B (R0)
