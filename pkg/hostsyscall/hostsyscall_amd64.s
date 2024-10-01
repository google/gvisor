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
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ a4+32(FP), R10
	MOVQ a5+40(FP), R8
	MOVQ a6+48(FP), R9
	MOVQ trap+0(FP), AX  // syscall entry
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JLS ok
	MOVQ $-1, r1+56(FP)
	NEGQ AX
	MOVQ AX, errno+64(FP)
	RET
ok:
	MOVQ AX, r1+56(FP)
	MOVQ $0, errno+64(FP)
	RET

// func RawSyscall(trap, a1, a2, a3 uintptr) (r1, errno)
TEXT ·RawSyscall(SB),NOSPLIT,$0-48
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ $0, R10
	MOVQ $0, R8
	MOVQ $0, R9
	MOVQ trap+0(FP), AX  // syscall entry
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JLS ok
	MOVQ $-1, r1+32(FP)
	NEGQ AX
	MOVQ AX, errno+40(FP)
	RET
ok:
	MOVQ AX, r1+32(FP)
	MOVQ $0, errno+40(FP)
	RET


// func RawSyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) (ret unix.Errno)
TEXT ·RawSyscallErrno6(SB),NOSPLIT,$0-64
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ a4+32(FP), R10
	MOVQ a5+40(FP), R8
	MOVQ a6+48(FP), R9
	MOVQ trap+0(FP), AX  // syscall entry
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JLS ok
	NEGQ AX
	MOVQ AX, ret+56(FP)
	RET
ok:
	MOVQ $0, ret+56(FP)
	RET

// func RawSyscallErrno(trap, a1, a2, a3 uintptr) (ret unix.Errno)
TEXT ·RawSyscallErrno(SB),NOSPLIT,$0-40
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ $0, R10
	MOVQ $0, R8
	MOVQ $0, R9
	MOVQ trap+0(FP), AX  // syscall entry
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JLS ok
	NEGQ AX
	MOVQ AX, ret+32(FP)
	RET
ok:
	MOVQ $0, ret+32(FP)
	RET
