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

// LoongArch Linux syscall ABI:
//   $a7 = R11    : syscall number
//   $a0..$a5     : R4..R9 (also receive return value in $a0)
//
// Errno detection: kernel returns -errno in $a0 for errors. The errno
// range is [-4095, -1]; treating $a0 as an unsigned 64-bit value, that
// range is [0xFFFFFFFFFFFFF001, 0xFFFFFFFFFFFFFFFF]. Anything below
// (unsigned) -4095 is a successful return.

// func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, errno uintptr)
TEXT ·RawSyscall6(SB),NOSPLIT,$0-72
	MOVV	trap+0(FP), R11
	MOVV	a1+8(FP), R4
	MOVV	a2+16(FP), R5
	MOVV	a3+24(FP), R6
	MOVV	a4+32(FP), R7
	MOVV	a5+40(FP), R8
	MOVV	a6+48(FP), R9
	SYSCALL
	MOVV	$-4095, R12
	BLTU	R4, R12, ok
	MOVV	$-1, R12
	MOVV	R12, r1+56(FP)
	SUBV	R4, R0, R4         // R4 = 0 - R4 = -R4 (positive errno)
	MOVV	R4, errno+64(FP)
	RET
ok:
	MOVV	R4, r1+56(FP)
	MOVV	R0, errno+64(FP)
	RET

// func RawSyscall(trap, a1, a2, a3 uintptr) (r1, errno uintptr)
TEXT ·RawSyscall(SB),NOSPLIT,$0-48
	MOVV	trap+0(FP), R11
	MOVV	a1+8(FP), R4
	MOVV	a2+16(FP), R5
	MOVV	a3+24(FP), R6
	MOVV	R0, R7
	MOVV	R0, R8
	MOVV	R0, R9
	SYSCALL
	MOVV	$-4095, R12
	BLTU	R4, R12, ok
	MOVV	$-1, R12
	MOVV	R12, r1+32(FP)
	SUBV	R4, R0, R4
	MOVV	R4, errno+40(FP)
	RET
ok:
	MOVV	R4, r1+32(FP)
	MOVV	R0, errno+40(FP)
	RET

// func RawSyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) (errno unix.Errno)
TEXT ·RawSyscallErrno6(SB),NOSPLIT,$0-64
	MOVV	trap+0(FP), R11
	MOVV	a1+8(FP), R4
	MOVV	a2+16(FP), R5
	MOVV	a3+24(FP), R6
	MOVV	a4+32(FP), R7
	MOVV	a5+40(FP), R8
	MOVV	a6+48(FP), R9
	SYSCALL
	MOVV	$-4095, R12
	BLTU	R4, R12, ok
	SUBV	R4, R0, R4
	MOVV	R4, ret+56(FP)
	RET
ok:
	MOVV	R0, ret+56(FP)
	RET

// func RawSyscallErrno(trap, a1, a2, a3 uintptr) (errno unix.Errno)
TEXT ·RawSyscallErrno(SB),NOSPLIT,$0-40
	MOVV	trap+0(FP), R11
	MOVV	a1+8(FP), R4
	MOVV	a2+16(FP), R5
	MOVV	a3+24(FP), R6
	MOVV	R0, R7
	MOVV	R0, R8
	MOVV	R0, R9
	SYSCALL
	MOVV	$-4095, R12
	BLTU	R4, R12, ok
	SUBV	R4, R0, R4
	MOVV	R4, ret+32(FP)
	RET
ok:
	MOVV	R0, ret+32(FP)
	RET
