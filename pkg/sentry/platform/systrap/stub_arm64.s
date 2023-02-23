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

#define SYS_GETPID       {{ .import.unix.Constants.SYS_GETPID }}
#define SYS_EXIT	 {{ .import.unix.Constants.SYS_EXIT }}
#define SYS_KILL	 {{ .import.unix.Constants.SYS_KILL }}
#define SYS_GETPPID	 {{ .import.unix.Constants.SYS_GETPPID }}
#define SIGKILL		 {{ .import.unix.Constants.SIGKILL }}
#define SIGSTOP		 {{ .import.unix.Constants.SIGSTOP }}
#define SYS_PRCTL	 {{ .import.unix.Constants.SYS_PRCTL }}
#define PR_SET_PDEATHSIG {{ .import.unix.Constants.PR_SET_PDEATHSIG }}

#define SYS_FUTEX	 {{ .import.unix.Constants.SYS_FUTEX }}
#define FUTEX_WAKE	 {{ .import.linux.Constants.FUTEX_WAKE }}
#define FUTEX_WAIT	 {{ .import.linux.Constants.FUTEX_WAIT }}

#define NEW_STUB	 {{ .Constants._NEW_STUB }}
#define RUN_SYSCALL_LOOP {{ .Constants._RUN_SYSCALL_LOOP }}

// syscallSentryMessage offsets.
#define SENTRY_MESSAGE_STATE {{ .syscallSentryMessage.state.Offset }}
#define SENTRY_MESSAGE_SYSNO {{ .syscallSentryMessage.sysno.Offset }}
#define SENTRY_MESSAGE_ARG0  ({{ .syscallSentryMessage.args.Offset }} + 0*8)
#define SENTRY_MESSAGE_ARG1  ({{ .syscallSentryMessage.args.Offset }} + 1*8)
#define SENTRY_MESSAGE_ARG2  ({{ .syscallSentryMessage.args.Offset }} + 2*8)
#define SENTRY_MESSAGE_ARG3  ({{ .syscallSentryMessage.args.Offset }} + 3*8)
#define SENTRY_MESSAGE_ARG4  ({{ .syscallSentryMessage.args.Offset }} + 4*8)
#define SENTRY_MESSAGE_ARG5  ({{ .syscallSentryMessage.args.Offset }} + 5*8)

// syscallStubMessage offsets.
#define STUB_MESSAGE_OFFSET {{ .Constants.syscallStubMessageOffset }}
#define STUB_MESSAGE_RET    {{ .syscallStubMessage.ret.Offset }}

// initStubProcess bootstraps the child and sends itself SIGSTOP to wait for attach.
//
// R7 contains the expected PPID.
//
// This should not be used outside the context of a new ptrace child (as the
// function is otherwise a bunch of nonsense).
TEXT ·initStubProcess(SB),NOSPLIT,$0
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

	// The sentry sets R9 to $NEW_STUB when creating stub process.
	CMP $NEW_STUB, R9
	BEQ clone

        // The sentry sets R9 to $RUN_SYSCALL_LOOP when creating a new syscall
        // thread.
	CMP $RUN_SYSCALL_LOOP, R9
	BEQ syscall_loop

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

	// syscall_loop handles requests from the Sentry to execute syscalls.
	// Look at syscall_thread for more details.
	//
	// syscall_loop is running without using the stack because it can be
	// compromised by sysmsg (guest) threads that run in the same address
	// space.
syscall_loop:
	// while (sentryMessage->state != R13) {
	// 	futex(sentryMessage->state, FUTEX_WAIT, 0, NULL, NULL, 0);
	// }
        MOVD R12, R0
	MOVD $FUTEX_WAIT, R1
	MOVD $0, R3
	MOVD $0, R4
	MOVD $0, R5
wait_for_syscall:
	// Move the sentry message state to R2.
	MOVW SENTRY_MESSAGE_STATE(R12), R2
	CMPW R2, R13
	BEQ execute_syscall

	MOVD $SYS_FUTEX, R8
	SVC
	JMP wait_for_syscall

execute_syscall:
	MOVD SENTRY_MESSAGE_SYSNO(R12), R8
	MOVD SENTRY_MESSAGE_ARG0(R12), R0
	MOVD SENTRY_MESSAGE_ARG1(R12), R1
	MOVD SENTRY_MESSAGE_ARG2(R12), R2
	MOVD SENTRY_MESSAGE_ARG3(R12), R3
	MOVD SENTRY_MESSAGE_ARG4(R12), R4
	MOVD SENTRY_MESSAGE_ARG5(R12), R5
        SVC

	// stubMessage->ret = ret
	MOVD R0, (STUB_MESSAGE_OFFSET + STUB_MESSAGE_RET)(R12)

	// for {
	//   if futex(sentryMessage->state, FUTEX_WAKE, 1) == 1 {
	//     break;
	//   }
	// }
	MOVD $FUTEX_WAKE, R1
	MOVD $1, R2
	MOVD $0, R3
	MOVD $0, R4
	MOVD $0, R5
	MOVD $SYS_FUTEX, R8
wake_up_sentry:
	MOVD R12, R0
	SVC

	// futex returns the number of waiters that were woken up.  If futex
	// returns 0 here, it means that the Sentry has not called futex_wait
	// yet and we need to try again. The value of sentryMessage->state
	// isn't changed, so futex_wake is the only way to wake up the Sentry.
	CMP $1, R0
	BNE wake_up_sentry

	ADDW $1, R13, R13
	JMP syscall_loop

// func addrOfInitStubProcess() uintptr
TEXT ·addrOfInitStubProcess(SB), $0-8
	MOVD	$·initStubProcess(SB), R0
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
