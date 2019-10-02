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
	BL	·callEntersyscallblock(SB)
	MOVD	fds+0(FP), R0
	MOVD	nfds+8(FP), R1
	MOVD	timeout+16(FP), R2
	MOVD	$0x0, R3  // sigmask parameter which isn't used here
	MOVD	$0x49, R8 // SYS_PPOLL
	SVC
	CMP	$0xfffffffffffff001, R0
	BLS	ok
	MOVD	$-1, R1
	MOVD	R1, n+24(FP)
	NEG	R0, R0
	MOVD	R0, err+32(FP)
	BL	·callExitsyscall(SB)
	RET
ok:
	MOVD	R0, n+24(FP)
	MOVD	$0, err+32(FP)
	BL	·callExitsyscall(SB)
	RET
