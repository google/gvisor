// Copyright 2023 The gVisor Authors.
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

//go:build amd64
// +build amd64

#include "textflag.h"

// calculateChecksum computes the checksum of a slice, taking into account a
// previously computed initial value and whether the first byte is a lower or
// upper byte.
//
// It utilizes byte order independence and parallel summation as described in
// RFC 1071 1.2.
//
// The best way to understand this function is to understand
// checksum_noasm_unsafe.go first, which implements largely the same logic.
// Using assembly speeds things up via ADC (add with carry).
TEXT ·calculateChecksumAMD64(SB),NOSPLIT|NOFRAME,$0-35
  // Store arguments in registers.
  MOVWQZX initial+26(FP), AX
  MOVQ buf_len+8(FP), BX
  MOVQ buf_base+0(FP), CX
  MOVBQZX odd+24(FP), R8

  // Account for a previous odd number of bytes.
  //
  // if odd {
  //   initial += buf[0]
  //   buf = buf[1:]
  // }
  CMPB R8, $0
  JE newlyodd
  MOVBQZX (CX), R9
  ADDW R9, AX
  ADCW $0, AX
  INCQ CX
  DECQ BX

  // See whether we're checksumming an odd number of bytes. If so, the final
  // byte is a big endian most significant byte, and so needs to be shifted.
  //
  // odd = buf_len%2 != 0
  // if odd {
  //   buf_len--
  //   initial += buf[buf_len]<<8
  // }
newlyodd:
  XORQ R8, R8
  TESTQ $1, BX
  JZ swaporder
  MOVB $1, R8
  DECQ BX
  MOVBQZX (CX)(BX*1), R10
  SHLQ $8, R10
  ADDW R10, AX
  ADCW $0, AX

swaporder:
  // Load initial in network byte order.
  XCHGB AH, AL

  // Handle any bytes that aren't 64-bit aligned. If the buffer starts at an
  // odd address, we just live with the alignment because doing otherwise
  // messes up the endianness expected by the below.
  //
  // while buf_len >= 2 && buf_base%8 != 0 {
  //   acc, carry = acc + *(uint16 *)(buf)
  //   buf_len -= 2
  //   buf = buf[2:]
  // }
unalignedaddloop:
  CMPQ BX, $2
  JB addloop
  TESTQ $7, CX
  JZ addloop
  MOVWQZX (CX), DX
  ADDQ DX, AX
  ADCQ $0, AX
  SUBQ $2, BX
  ADDQ $2, CX
  JMP unalignedaddloop

  // Accumulate 8 bytes at a time.
  //
  // while buf_len >= 8 {
  //   acc, carry = acc + *(uint64 *)(buf) + carry
  //   buf_len -= 8
  //   buf = buf[8:]
  // }
  // acc += carry
addloop:
  CMPQ BX, $8
  JB slowaddloop
  ADDQ (CX), AX
  ADCQ $0, AX
  SUBQ $8, BX
  ADDQ $8, CX
  JMP addloop

  // TODO(krakauer): We can do 4 byte accumulation too.

  // Accumulate the rest 2 bytes at a time.
  //
  // while buf_len >= 2 {
  //   acc, carry = acc + *(uint16 *)(buf)
  //   buf_len -= 2
  //   buf = buf[2:]
  // }
slowaddloop:
  CMPQ BX, $2
  JB foldloop
  MOVWQZX (CX), DX
  ADDQ DX, AX
  ADCQ $0, AX
  SUBQ $2, BX
  ADDQ $2, CX
  JMP slowaddloop

  // Fold into 16 bits.
  //
  // for acc > math.MaxUint16 {
  //   acc = (acc & 0xffff) + acc>>16
  // }
foldloop:
  CMPQ AX, $0xffff
  JBE finalswap
  MOVQ AX, DX
  ANDQ $0xffff, DX
  SHRQ $16, AX
  ADDQ DX, AX
  JMP foldloop
  // We don't need ADC because folding will take care of it

finalswap:
  // Return the checksum in host byte order.
  XCHGB AH, AL
  MOVW AX, ret+32(FP)
  MOVB R8, ret1+34(FP)
  RET
