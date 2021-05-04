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

// handleSwapUint32Fault returns the value stored in DI. Control is transferred
// to it when swapUint32 below receives SIGSEGV or SIGBUS, with the signal
// number stored in DI.
//
// It must have the same frame configuration as swapUint32 so that it can undo
// any potential call frame set up by the assembler.
TEXT handleSwapUint32Fault(SB), NOSPLIT, $0-24
  MOVL DI, sig+20(FP)
  RET

// swapUint32 atomically stores new into *ptr and returns (the previous ptr*
// value, 0). If a SIGSEGV or SIGBUS signal is received during the swap, the
// value of old is unspecified, and sig is the number of the signal that was
// received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//func swapUint32(ptr unsafe.Pointer, new uint32) (old uint32, sig int32)
TEXT ·swapUint32(SB), NOSPLIT, $0-24
  // Store 0 as the returned signal number. If we run to completion,
  // this is the value the caller will see; if a signal is received,
  // handleSwapUint32Fault will store a different value in this address.
  MOVL $0, sig+20(FP)

  MOVQ ptr+0(FP), DI
  MOVL new+8(FP), AX
  XCHGL AX, 0(DI)
  MOVL AX, old+16(FP)
  RET

// func addrOfSwapUint32() uintptr
TEXT ·addrOfSwapUint32(SB), $0-8
  MOVQ $·swapUint32(SB), AX
  MOVQ AX, ret+0(FP)
  RET

// handleSwapUint64Fault returns the value stored in DI. Control is transferred
// to it when swapUint64 below receives SIGSEGV or SIGBUS, with the signal
// number stored in DI.
//
// It must have the same frame configuration as swapUint64 so that it can undo
// any potential call frame set up by the assembler.
TEXT handleSwapUint64Fault(SB), NOSPLIT, $0-28
  MOVL DI, sig+24(FP)
  RET

// swapUint64 atomically stores new into *ptr and returns (the previous *ptr
// value, 0). If a SIGSEGV or SIGBUS signal is received during the swap, the
// value of old is unspecified, and sig is the number of the signal that was
// received.
//
// Preconditions: ptr must be aligned to a 8-byte boundary.
//
//func swapUint64(ptr unsafe.Pointer, new uint64) (old uint64, sig int32)
TEXT ·swapUint64(SB), NOSPLIT, $0-28
  // Store 0 as the returned signal number. If we run to completion,
  // this is the value the caller will see; if a signal is received,
  // handleSwapUint64Fault will store a different value in this address.
  MOVL $0, sig+24(FP)

  MOVQ ptr+0(FP), DI
  MOVQ new+8(FP), AX
  XCHGQ AX, 0(DI)
  MOVQ AX, old+16(FP)
  RET

// func addrOfSwapUint64() uintptr
TEXT ·addrOfSwapUint64(SB), $0-8
  MOVQ $·swapUint64(SB), AX
  MOVQ AX, ret+0(FP)
  RET

// handleCompareAndSwapUint32Fault returns the value stored in DI. Control is
// transferred to it when swapUint64 below receives SIGSEGV or SIGBUS, with the
// signal number stored in DI.
//
// It must have the same frame configuration as compareAndSwapUint32 so that it
// can undo any potential call frame set up by the assembler.
TEXT handleCompareAndSwapUint32Fault(SB), NOSPLIT, $0-24
  MOVL DI, sig+20(FP)
  RET

// compareAndSwapUint32 is like sync/atomic.CompareAndSwapUint32, but returns
// (the value previously stored at ptr, 0). If a SIGSEGV or SIGBUS signal is
// received during the operation, the value of prev is unspecified, and sig is
// the number of the signal that was received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//func compareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (prev uint32, sig int32)
TEXT ·compareAndSwapUint32(SB), NOSPLIT, $0-24
  // Store 0 as the returned signal number. If we run to completion, this is
  // the value the caller will see; if a signal is received,
  // handleCompareAndSwapUint32Fault will store a different value in this
  // address.
  MOVL $0, sig+20(FP)

  MOVQ ptr+0(FP), DI
  MOVL old+8(FP), AX
  MOVL new+12(FP), DX
  LOCK
  CMPXCHGL DX, 0(DI)
  MOVL AX, prev+16(FP)
  RET

// func addrOfCompareAndSwapUint32() uintptr
TEXT ·addrOfCompareAndSwapUint32(SB), $0-8
  MOVQ $·compareAndSwapUint32(SB), AX
  MOVQ AX, ret+0(FP)
  RET

// handleLoadUint32Fault returns the value stored in DI. Control is transferred
// to it when LoadUint32 below receives SIGSEGV or SIGBUS, with the signal
// number stored in DI.
//
// It must have the same frame configuration as loadUint32 so that it can undo
// any potential call frame set up by the assembler.
TEXT handleLoadUint32Fault(SB), NOSPLIT, $0-16
  MOVL DI, sig+12(FP)
  RET

// loadUint32 atomically loads *ptr and returns it. If a SIGSEGV or SIGBUS
// signal is received, the value returned is unspecified, and sig is the number
// of the signal that was received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//func loadUint32(ptr unsafe.Pointer) (val uint32, sig int32)
TEXT ·loadUint32(SB), NOSPLIT, $0-16
  // Store 0 as the returned signal number. If we run to completion,
  // this is the value the caller will see; if a signal is received,
  // handleLoadUint32Fault will store a different value in this address.
  MOVL $0, sig+12(FP)

  MOVQ ptr+0(FP), AX
  MOVL (AX), BX
  MOVL BX, val+8(FP)
  RET

// func addrOfLoadUint32() uintptr
TEXT ·addrOfLoadUint32(SB), $0-8
  MOVQ $·loadUint32(SB), AX
  MOVQ AX, ret+0(FP)
  RET
