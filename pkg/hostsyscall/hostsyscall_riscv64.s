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
	MOV trap+0(FP), A7   // syscall entry
	MOV a1+8(FP), A0
	MOV a2+16(FP), A1
	MOV a3+24(FP), A2
	MOV a4+32(FP), A3
	MOV a5+40(FP), A4
	MOV a6+48(FP), A5
	ECALL
	MOV $-4096, T0
	BLTU T0, A0, err6
	MOV A0, r1+56(FP)
	MOV ZERO, errno+64(FP)
	RET
err6:
	MOV $-1, T0
	MOV T0, r1+56(FP)
	NEG A0, A0
	MOV A0, errno+64(FP)
	RET

// func RawSyscall(trap, a1, a2, a3 uintptr) (r1, errno)
TEXT ·RawSyscall(SB),NOSPLIT,$0-48
	MOV trap+0(FP), A7   // syscall entry
	MOV a1+8(FP), A0
	MOV a2+16(FP), A1
	MOV a3+24(FP), A2
	MOV ZERO, A3
	MOV ZERO, A4
	MOV ZERO, A5
	ECALL
	MOV $-4096, T0
	BLTU T0, A0, err3
	MOV A0, r1+32(FP)
	MOV ZERO, errno+40(FP)
	RET
err3:
	MOV $-1, T0
	MOV T0, r1+32(FP)
	NEG A0, A0
	MOV A0, errno+40(FP)
	RET

// func RawSyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) (errno unix.Errno)
TEXT ·RawSyscallErrno6(SB),NOSPLIT,$0-64
	MOV trap+0(FP), A7   // syscall entry
	MOV a1+8(FP), A0
	MOV a2+16(FP), A1
	MOV a3+24(FP), A2
	MOV a4+32(FP), A3
	MOV a5+40(FP), A4
	MOV a6+48(FP), A5
	ECALL
	MOV $-4096, T0
	BLTU T0, A0, errerr6
	MOV ZERO, ret+56(FP) // errno
	RET
errerr6:
	NEG A0, A0
	MOV A0, ret+56(FP) // errno
	RET

// func RawSyscallErrno(trap, a1, a2, a3 uintptr) (errno unix.Errno)
TEXT ·RawSyscallErrno(SB),NOSPLIT,$0-40
	MOV trap+0(FP), A7   // syscall entry
	MOV a1+8(FP), A0
	MOV a2+16(FP), A1
	MOV a3+24(FP), A2
	MOV ZERO, A3
	MOV ZERO, A4
	MOV ZERO, A5
	ECALL
	MOV $-4096, T0
	BLTU T0, A0, errerr3
	MOV ZERO, ret+32(FP) // errno
	RET
errerr3:
	NEG A0, A0
	MOV A0, ret+32(FP) // errno
	RET
