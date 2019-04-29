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

#include "funcdata.h"
#include "textflag.h"

#define SYS_GETPID		39
#define SYS_EXIT		60
#define SYS_KILL		62
#define SYS_GETPPID		110
#define SYS_PRCTL		157

#define SIGKILL			9
#define SIGSTOP			19

#define PR_SET_PDEATHSIG	1

// stub bootstraps the child and sends itself SIGSTOP to wait for attach.
//
// R15 contains the expected PPID. R15 is used instead of a more typical DI
// since syscalls will clobber DI and createStub wants to pass a new PPID to
// grandchildren.
//
// This should not be used outside the context of a new ptrace child (as the
// function is otherwise a bunch of nonsense).
TEXT ·stub(SB),NOSPLIT,$0
begin:
	// N.B. This loop only executes in the context of a single-threaded
	// fork child.

	MOVQ $SYS_PRCTL, AX
	MOVQ $PR_SET_PDEATHSIG, DI
	MOVQ $SIGKILL, SI
	SYSCALL

	CMPQ AX, $0
	JNE error

	// If the parent already died before we called PR_SET_DEATHSIG then
	// we'll have an unexpected PPID.
	MOVQ $SYS_GETPPID, AX
	SYSCALL

	CMPQ AX, $0
	JL error

	CMPQ AX, R15
	JNE parent_dead

	MOVQ $SYS_GETPID, AX
	SYSCALL

	CMPQ AX, $0
	JL error

	// SIGSTOP to wait for attach.
	//
	// The SYSCALL instruction will be used for future syscall injection by
	// thread.syscall.
	MOVQ AX, DI
	MOVQ $SYS_KILL, AX
	MOVQ $SIGSTOP, SI
	SYSCALL

	// The tracer may "detach" and/or allow code execution here in three cases:
	//
	// 1. New (traced) stub threads are explicitly detached by the
	// goroutine in newSubprocess. However, they are detached while in
	// group-stop, so they do not execute code here.
	//
	// 2. If a tracer thread exits, it implicitly detaches from the stub,
	// potentially allowing code execution here. However, the Go runtime
	// never exits individual threads, so this case never occurs.
	//
	// 3. subprocess.createStub clones a new stub process that is untraced,
	// thus executing this code. We setup the PDEATHSIG before SIGSTOPing
	// ourselves for attach by the tracer.
	//
	// R15 has been updated with the expected PPID.
	JMP begin

error:
	// Exit with -errno.
	MOVQ AX, DI
	NEGQ DI
	MOVQ $SYS_EXIT, AX
	SYSCALL
	HLT

parent_dead:
	MOVQ $SYS_EXIT, AX
	MOVQ $1, DI
	SYSCALL
	HLT

// stubCall calls the stub function at the given address with the given PPID.
//
// This is a distinct function because stub, above, may be mapped at any
// arbitrary location, and stub has a specific binary API (see above).
TEXT ·stubCall(SB),NOSPLIT,$0-16
	MOVQ addr+0(FP), AX
	MOVQ pid+8(FP), R15
	JMP AX
