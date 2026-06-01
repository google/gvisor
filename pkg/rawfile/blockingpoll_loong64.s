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

#include "textflag.h"

// BlockingPoll wraps the ppoll(2) syscall while bracketing it with
// runtime.callEntersyscallblock / runtime.callExitsyscall so other Gs can
// be scheduled onto our P while the syscall is blocked.
//
// SYS_PPOLL = 73 in the asm-generic syscall table (identical to arm64).
//
// func BlockingPoll(fds *PollEvent, nfds int, timeout *syscall.Timespec) (n int, err syscall.Errno)
TEXT ·BlockingPoll(SB),NOSPLIT,$0-40
	CALL	·callEntersyscallblock(SB)
	MOVV	fds+0(FP), R4
	MOVV	nfds+8(FP), R5
	MOVV	timeout+16(FP), R6
	MOVV	R0, R7              // sigmask = NULL
	MOVV	$73, R11            // SYS_PPOLL
	SYSCALL
	MOVV	$-4095, R12
	BLTU	R4, R12, ok
	MOVV	$-1, R12
	MOVV	R12, ret+24(FP)
	SUBV	R4, R0, R4          // R4 = -R4 (positive errno)
	MOVV	R4, ret1+32(FP)
	CALL	·callExitsyscall(SB)
	RET
ok:
	MOVV	R4, ret+24(FP)
	MOVV	R0, ret1+32(FP)
	CALL	·callExitsyscall(SB)
	RET
