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

#define SYS_GETPID       172 // +checkconst unix SYS_GETPID
#define SYS_EXIT	 93  // +checkconst unix SYS_EXIT
#define SYS_KILL	 129 // +checkconst unix SYS_KILL
#define SYS_GETPPID	 173 // +checkconst unix SYS_GETPPID
#define SIGKILL		 9   // +checkconst unix SIGKILL
#define SIGSTOP		 19  // +checkconst unix SIGSTOP
#define SYS_PRCTL	 167 // +checkconst unix SYS_PRCTL
#define PR_SET_PDEATHSIG 1   // +checkconst unix PR_SET_PDEATHSIG

#define SYS_FUTEX	 98 // +checkconst unix SYS_FUTEX
#define FUTEX_WAKE	 1  // +checkconst linux FUTEX_WAKE
#define FUTEX_WAIT	 0  // +checkconst linux FUTEX_WAIT

#define NEW_STUB	 1 // +checkconst . _NEW_STUB
#define RUN_SYSCALL_LOOP 5 // +checkconst . _RUN_SYSCALL_LOOP

// syscallSentryMessage offsets.
#define SENTRY_MESSAGE_STATE 0  // +checkoffset . syscallSentryMessage.state
#define SENTRY_MESSAGE_SYSNO 8  // +checkoffset . syscallSentryMessage.sysno
#define SENTRY_MESSAGE_ARGS  16 // +checkoffset . syscallSentryMessage.args
#define SENTRY_MESSAGE_ARG0  (SENTRY_MESSAGE_ARGS + 0*8)
#define SENTRY_MESSAGE_ARG1  (SENTRY_MESSAGE_ARGS + 1*8)
#define SENTRY_MESSAGE_ARG2  (SENTRY_MESSAGE_ARGS + 2*8)
#define SENTRY_MESSAGE_ARG3  (SENTRY_MESSAGE_ARGS + 3*8)
#define SENTRY_MESSAGE_ARG4  (SENTRY_MESSAGE_ARGS + 4*8)
#define SENTRY_MESSAGE_ARG5  (SENTRY_MESSAGE_ARGS + 5*8)

// syscallStubMessage offsets.
#define STUB_MESSAGE_OFFSET 4096 // +checkconst . syscallStubMessageOffset
#define STUB_MESSAGE_RET    0    // +checkoffset . syscallStubMessage.ret

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

	// The sentry sets S8 to $NEW_STUB when creating stub process.
	MOV  $NEW_STUB, T0
	BEQ T0, S8, clone

        // The sentry sets S8 to $RUN_SYSCALL_LOOP when creating a new syscall
        // thread.
	MOV $RUN_SYSCALL_LOOP, T0
	BEQ T0, S8, syscall_loop

done:
	// Notify the Sentry that syscall exited.
	EBREAK
	JMP done // Be paranoid.
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

	// syscall_loop handles requests from the Sentry to execute syscalls.
	// Look at syscall_thread for more details.
	//
	// syscall_loop is running without using the stack because it can be
	// compromised by sysmsg (guest) threads that run in the same address
	// space.
syscall_loop:
	// while (sentryMessage->state != S10) {
	// 	futex(sentryMessage->state, FUTEX_WAIT, 0, NULL, NULL, 0);
	// }
	MOV $FUTEX_WAIT, A1
	MOV $0, A2
	MOV $0, A3
	MOV $0, A4
wait_for_syscall:
	// Move the sentry message state to A2.
	MOVW SENTRY_MESSAGE_STATE(S9), A2
	BEQ A2, S10, execute_syscall

        MOV S9, A0
	MOV $SYS_FUTEX, A7
	ECALL
	JMP wait_for_syscall

execute_syscall:
	MOV  SENTRY_MESSAGE_SYSNO(S9), A7
	MOV  SENTRY_MESSAGE_ARG0(S9), A0
	MOV  SENTRY_MESSAGE_ARG1(S9), A1
	MOV  SENTRY_MESSAGE_ARG2(S9), A2
	MOV  SENTRY_MESSAGE_ARG3(S9), A3
	MOV  SENTRY_MESSAGE_ARG4(S9), A4
	MOV  SENTRY_MESSAGE_ARG5(S9), A5
        ECALL

	// stubMessage->ret = ret
	MOV A0, (STUB_MESSAGE_OFFSET + STUB_MESSAGE_RET)(S9)

	// for {
	//   if futex(sentryMessage->state, FUTEX_WAKE, 1) == 1 {
	//     break;
	//   }
	// }
	MOV $FUTEX_WAKE, A1
	MOV $1, A2
	MOV $0, A3
	MOV $0, A4
	MOV $0, A5
	MOV $SYS_FUTEX, A7
wake_up_sentry:
	MOV S9, A0
	ECALL

	// futex returns the number of waiters that were woken up.  If futex
	// returns 0 here, it means that the Sentry has not called futex_wait
	// yet and we need to try again. The value of sentryMessage->state
	// isn't changed, so futex_wake is the only way to wake up the Sentry.
	MOV $1, T0
	BNE T0, A0, wake_up_sentry

	ADDI $1, S10, S10
	JMP syscall_loop

// func addrOfInitStubProcess() uintptr
TEXT ·addrOfInitStubProcess(SB), $0-8
	MOV	$·initStubProcess(SB), A0
	MOV	A0, ret+0(FP)
	RET

// stubCall calls the stub function at the given address with the given PPID.
//
// This is a distinct function because stub, above, may be mapped at any
// arbitrary location, and stub has a specific binary API (see above).
TEXT ·stubCall(SB),NOSPLIT,$0-16
	MOV  addr+0(FP), A0
	MOV  pid+8(FP), S7
	JMP (A0)
