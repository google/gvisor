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

// func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, errno)
TEXT ·Syscall6(SB),NOSPLIT,$0-80
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
	MOVQ $0, r2+64(FP)
	NEGQ AX
	MOVQ AX, errno+72(FP)
	RET
ok:
	MOVQ AX, r1+56(FP)
	MOVQ DX, r2+64(FP)
	MOVQ $0, errno+72(FP)
	RET

// func SyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) (ret unix.Errno)
TEXT ·SyscallErrno6(SB),NOSPLIT,$0-64
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

// func SyscallErrno(trap, a1, a2, a3 uintptr) (ret unix.Errno)
TEXT ·SyscallErrno(SB),NOSPLIT,$0-40
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
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
