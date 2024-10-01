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

// func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, errno)
TEXT ·RawSyscall6(SB),NOSPLIT,$0-72
	MOVD trap+0(FP), R8   // syscall entry
	MOVD a1+8(FP), R0
	MOVD a2+16(FP), R1
	MOVD a3+24(FP), R2
	MOVD a4+32(FP), R3
	MOVD a5+40(FP), R4
	MOVD a6+48(FP), R5
	SVC
	CMN $4095, R0
	BCC ok
	MOVD $-1, R4
	MOVD R4, r1+56(FP)
	NEG R0, R0
	MOVD R0, errno+64(FP)
	RET
ok:
	MOVD R0, r1+56(FP)
	MOVD ZR, errno+64(FP)
	RET

// func RawSyscall(trap, a1, a2, a3 uintptr) (r1, errno)
TEXT ·RawSyscall(SB),NOSPLIT,$0-48
	MOVD trap+0(FP), R8   // syscall entry
	MOVD a1+8(FP), R0
	MOVD a2+16(FP), R1
	MOVD a3+24(FP), R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD ZR, R5
	SVC
	CMN $4095, R0
	BCC ok
	MOVD $-1, R4
	MOVD R4, r1+32(FP)
	NEG R0, R0
	MOVD R0, errno+40(FP)
	RET
ok:
	MOVD R0, r1+32(FP)
	MOVD ZR, errno+40(FP)
	RET

// func RawSyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) (errno unix.Errno)
TEXT ·RawSyscallErrno6(SB),NOSPLIT,$0-64
	MOVD trap+0(FP), R8   // syscall entry
	MOVD a1+8(FP), R0
	MOVD a2+16(FP), R1
	MOVD a3+24(FP), R2
	MOVD a4+32(FP), R3
	MOVD a5+40(FP), R4
	MOVD a6+48(FP), R5
	SVC
	CMN $4095, R0
	BCC ok
	NEG R0, R0
	MOVD R0, ret+56(FP) // errno
	RET
ok:
	MOVD ZR, ret+56(FP) // errno
	RET

// func RawSyscallErrno(trap, a1, a2, a3 uintptr) (errno unix.Errno)
TEXT ·RawSyscallErrno(SB),NOSPLIT,$0-40
	MOVD trap+0(FP), R8   // syscall entry
	MOVD a1+8(FP), R0
	MOVD a2+16(FP), R1
	MOVD a3+24(FP), R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD ZR, R5
	SVC
	CMN $4095, R0
	BCC ok
	NEG R0, R0
	MOVD R0, ret+32(FP) // errno
	RET
ok:
	MOVD ZR, ret+32(FP) // errno
	RET
