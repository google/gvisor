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

// Package bpf provides tools for working with Berkeley Packet Filter (BPF)
// programs. More information on BPF can be found at
// https://www.freebsd.org/cgi/man.cgi?bpf(4)
package bpf

import "gvisor.googlesource.com/gvisor/pkg/abi/linux"

const (
	// MaxInstructions is the maximum number of instructions in a BPF program,
	// and is equal to Linux's BPF_MAXINSNS.
	MaxInstructions = 4096

	// ScratchMemRegisters is the number of M registers in a BPF virtual machine,
	// and is equal to Linux's BPF_MEMWORDS.
	ScratchMemRegisters = 16
)

// Parts of a linux.BPFInstruction.OpCode. Compare to the Linux kernel's
// include/uapi/linux/filter.h.
//
// In the comments below:
//
// - A, X, and M[] are BPF virtual machine registers.
//
// - K refers to the instruction field linux.BPFInstruction.K.
//
// - Bits are counted from the LSB position.
const (
	// Instruction class, stored in bits 0-2.
	Ld                   = 0x00 // load into A
	Ldx                  = 0x01 // load into X
	St                   = 0x02 // store from A
	Stx                  = 0x03 // store from X
	Alu                  = 0x04 // arithmetic
	Jmp                  = 0x05 // jump
	Ret                  = 0x06 // return
	Misc                 = 0x07
	instructionClassMask = 0x07

	// Size of a load, stored in bits 3-4.
	W            = 0x00 // 32 bits
	H            = 0x08 // 16 bits
	B            = 0x10 // 8 bits
	loadSizeMask = 0x18

	// Source operand for a load, stored in bits 5-7.
	// Address mode numbers in the comments come from Linux's
	// Documentation/networking/filter.txt.
	Imm          = 0x00 // immediate value K (mode 4)
	Abs          = 0x20 // data in input at byte offset K (mode 1)
	Ind          = 0x40 // data in input at byte offset X+K (mode 2)
	Mem          = 0x60 // M[K] (mode 3)
	Len          = 0x80 // length of the input in bytes ("BPF extension len")
	Msh          = 0xa0 // 4 * lower nibble of input at byte offset K (mode 5)
	loadModeMask = 0xe0

	// Source operands for arithmetic, jump, and return instructions.
	// Arithmetic and jump instructions can use K or X as source operands.
	// Return instructions can use K or A as source operands.
	K             = 0x00 // still mode 4
	X             = 0x08 // mode 0
	A             = 0x10 // mode 9
	srcAluJmpMask = 0x08
	srcRetMask    = 0x18

	// Arithmetic instructions, stored in bits 4-7.
	Add     = 0x00
	Sub     = 0x10 // A - src
	Mul     = 0x20
	Div     = 0x30 // A / src
	Or      = 0x40
	And     = 0x50
	Lsh     = 0x60 // A << src
	Rsh     = 0x70 // A >> src
	Neg     = 0x80 // -A (src ignored)
	Mod     = 0x90 // A % src
	Xor     = 0xa0
	aluMask = 0xf0

	// Jump instructions, stored in bits 4-7.
	Ja      = 0x00 // unconditional (uses K for jump offset)
	Jeq     = 0x10 // if A == src
	Jgt     = 0x20 // if A > src
	Jge     = 0x30 // if A >= src
	Jset    = 0x40 // if (A & src) != 0
	jmpMask = 0xf0

	// Miscellaneous instructions, stored in bits 3-7.
	Tax      = 0x00 // A = X
	Txa      = 0x80 // X = A
	miscMask = 0xf8

	// Masks for bits that should be zero.
	unusedBitsMask      = 0xff00 // all valid instructions use only bits 0-7
	storeUnusedBitsMask = 0xf8   // stores only use instruction class
	retUnusedBitsMask   = 0xe0   // returns only use instruction class and source operand
)

// Stmt returns a linux.BPFInstruction representing a BPF non-jump instruction.
func Stmt(code uint16, k uint32) linux.BPFInstruction {
	return linux.BPFInstruction{
		OpCode: code,
		K:      k,
	}
}

// Jump returns a linux.BPFInstruction representing a BPF jump instruction.
func Jump(code uint16, k uint32, jt, jf uint8) linux.BPFInstruction {
	return linux.BPFInstruction{
		OpCode:      code,
		JumpIfTrue:  jt,
		JumpIfFalse: jf,
		K:           k,
	}
}
