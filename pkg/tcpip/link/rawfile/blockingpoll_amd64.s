// Copyright 2018 Google Inc.
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

// blockingPoll makes the poll() syscall while calling the version of
// entersyscall that relinquishes the P so that other Gs can run. This is meant
// to be called in cases when the syscall is expected to block.
//
// func blockingPoll(fds *pollEvent, nfds int, timeout int64) (n int, err syscall.Errno)
TEXT ·blockingPoll(SB),NOSPLIT,$0-40
	CALL	runtime·entersyscallblock(SB)
	MOVQ	fds+0(FP), DI
	MOVQ	nfds+8(FP), SI
	MOVQ	timeout+16(FP), DX
	MOVQ	$0x7, AX // SYS_POLL
	SYSCALL
	CMPQ	AX, $0xfffffffffffff001
	JLS	ok
	MOVQ	$-1, n+24(FP)
	NEGQ	AX
	MOVQ	AX, err+32(FP)
	CALL	runtime·exitsyscall(SB)
	RET
ok:
	MOVQ	AX, n+24(FP)
	MOVQ	$0, err+32(FP)
	CALL	runtime·exitsyscall(SB)
	RET
