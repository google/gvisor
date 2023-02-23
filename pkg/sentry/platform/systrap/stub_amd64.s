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
// R15 contains the expected PPID. R15 is used instead of a more typical DI
// since syscalls will clobber DI and createStub wants to pass a new PPID to
// grandchildren.
//
// This should not be used outside the context of a new ptrace child (as the
// function is otherwise a bunch of nonsense).
TEXT ·initStubProcess(SB),NOSPLIT,$0
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

	MOVQ $0, BX

	// SIGSTOP to wait for attach.
	//
	// The SYSCALL instruction will be used for future syscall injection by
	// thread.syscall.
	MOVQ AX, DI
	MOVQ $SYS_KILL, AX
	MOVQ $SIGSTOP, SI
	SYSCALL

	// The sentry sets BX to $NEW_STUB when creating stub process.
	CMPQ BX, $NEW_STUB
	JE clone

	// The sentry sets BX to $RUN_SYSCALL_LOOP when requesting a syscall
        // thread.
	CMPQ BX, $RUN_SYSCALL_LOOP
	JE syscall_loop

	// Notify the Sentry that syscall exited.
done:
	INT $3
	// Be paranoid.
	JMP done
clone:
	// subprocess.createStub clones a new stub process that is untraced,
	// thus executing this code. We setup the PDEATHSIG before SIGSTOPing
	// ourselves for attach by the tracer.
	//
	// R15 has been updated with the expected PPID.
	CMPQ AX, $0
	JE begin

	// The clone syscall returns a non-zero value.
	JMP done
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
	MOVQ R12, DI
	MOVQ $FUTEX_WAIT, SI
	MOVQ $0, R10
	MOVQ $0, R8
	MOVQ $0, R9
wait_for_syscall:
	MOVL SENTRY_MESSAGE_STATE(DI), DX
	CMPL DX, R13
	JE execute_syscall

	MOVQ $SYS_FUTEX, AX
	SYSCALL
	JMP wait_for_syscall

execute_syscall:
	// ret = syscall(sysno, args...)
	MOVQ SENTRY_MESSAGE_SYSNO(R12), AX
	MOVQ SENTRY_MESSAGE_ARG0(R12), DI
	MOVQ SENTRY_MESSAGE_ARG1(R12), SI
	MOVQ SENTRY_MESSAGE_ARG2(R12), DX
	MOVQ SENTRY_MESSAGE_ARG3(R12), R10
	MOVQ SENTRY_MESSAGE_ARG4(R12), R8
	MOVQ SENTRY_MESSAGE_ARG5(R12), R9
	SYSCALL

	// stubMessage->ret = ret
	MOVQ AX, (STUB_MESSAGE_OFFSET + STUB_MESSAGE_RET)(R12)

	// for {
	//   if futex(sentryMessage->state, FUTEX_WAKE, 1) == 1 {
	//     break;
	//   }
	// }
	MOVQ R12, DI
	MOVQ $FUTEX_WAKE, SI
	MOVQ $1, DX
	MOVQ $0, R10
	MOVQ $0, R8
	MOVQ $0, R9
wake_up_sentry:
	MOVQ $SYS_FUTEX, AX
	SYSCALL
	// futex returns the number of waiters that were woken up.  If futex
	// returns 0 here, it means that the Sentry has not called futex_wait
	// yet and we need to try again. The value of sentryMessage->state
	// isn't changed, so futex_wake is the only way to wake up the Sentry.
	CMPQ AX, $1
	JNE wake_up_sentry

	INCL R13
	JMP syscall_loop

// func addrOfInitStubProcess() uintptr
TEXT ·addrOfInitStubProcess(SB), $0-8
	MOVQ $·initStubProcess(SB), AX
	MOVQ AX, ret+0(FP)
	RET

// stubCall calls the stub function at the given address with the given PPID.
//
// This is a distinct function because stub, above, may be mapped at any
// arbitrary location, and stub has a specific binary API (see above).
TEXT ·stubCall(SB),NOSPLIT,$0-16
	MOVQ addr+0(FP), AX
	MOVQ pid+8(FP), R15
	JMP AX
