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

#include "textflag.h"

// BlockingPoll makes the ppoll() syscall while calling the version of
// entersyscall that relinquishes the P so that other Gs can run. This is meant
// to be called in cases when the syscall is expected to block.
//
// func BlockingPoll(fds *PollEvent, nfds int, timeout *syscall.Timespec) (n int, err syscall.Errno)
TEXT ·BlockingPoll(SB),NOSPLIT,$0-40
	CALL	·callEntersyscallblock(SB)
	MOV	fds+0(FP), A0
	MOV	nfds+8(FP), A1
	MOV	timeout+16(FP), A2
	MOV	$0x0, A3  // sigmask parameter which isn't used here
	MOV	$0x49, A7 // SYS_PPOLL
	ECALL
	MOV	$0xfffffffffffff002, T0
	BLT	T0, A0, ok
	MOV	$-1, A1
	MOV	A1, ret+24(FP)
	NEG	A0, A0
	MOV	A0, ret1+32(FP)
	CALL	·callExitsyscall(SB)
	RET
ok:
	MOV	A0, ret+24(FP)
	MOV	ZERO, ret1+32(FP)
	CALL	·callExitsyscall(SB)
	RET
