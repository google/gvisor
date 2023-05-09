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
TEXT ·BlockingPoll(SB),NOSPLIT|NOFRAME,$0-40
	CALL	·callEntersyscallblock(SB)
	MOVQ	fds+0(FP), DI
	MOVQ	nfds+8(FP), SI
	MOVQ	timeout+16(FP), DX
	MOVQ	$0x0, R10  // sigmask parameter which isn't used here
	MOVQ	$0x10f, AX // SYS_PPOLL
	SYSCALL
	CMPQ	AX, $0xfffffffffffff002
	JLS	ok
	MOVQ	$-1, ret+24(FP)
	NEGQ	AX
	MOVQ	AX, ret1+32(FP)
	CALL	·callExitsyscall(SB)
	RET
ok:
	MOVQ	AX, ret+24(FP)
	MOVQ	$0, ret1+32(FP)
	CALL	·callExitsyscall(SB)
	RET
