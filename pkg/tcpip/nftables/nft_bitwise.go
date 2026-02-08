// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// bitwiseOp is the bitwise operator for a bitwise operation.
// Note: corresponds to enum nft_bitwise_ops from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type bitwiseOp int

// bitwiseOpStrings is a map of bitwiseOp to its string representation.
var bitwiseOpStrings = map[bitwiseOp]string{
	linux.NFT_BITWISE_BOOL:   "bitwise boolean",
	linux.NFT_BITWISE_LSHIFT: "bitwise <<",
	linux.NFT_BITWISE_RSHIFT: "bitwise >>",
}

// String for bitwiseOp returns the string representation of the bitwise
// operator.
func (bop bitwiseOp) String() string {
	if str, ok := bitwiseOpStrings[bop]; ok {
		return str
	}
	panic(fmt.Sprintf("invalid bitwise operator: %d", int(bop)))
}

// bitwise is an operation that performs bitwise math operations over data in
// a given register, storing the result in a destination register.
// Note: bitwise operations are not supported for the verdict register.
type bitwise struct {
	sreg  uint8     // Number of the source register.
	dreg  uint8     // Number of the destination register.
	bop   bitwiseOp // Bitwise operator to use.
	blen  uint8     // Number of bytes to apply bitwise operation to.
	mask  bytesData // Mask to apply bitwise & for boolean operations (before ^).
	xor   bytesData // Xor to apply bitwise ^ for boolean operations (after &).
	shift uint32    // Shift to apply bitwise <</>> for non-boolean operations.

	// Note: Technically, the linux kernel has defined bool, lshift, and rshift
	// as the 3 types of bitwise operations. However, we have not been able to
	// observe the lshift or rshift operations used by the nft binary. Thus, we
	// have no way to test the interpretation of these operations. Maintaining
	// consistency with the linux kernel, we have fully implemented lshift and
	// rshift, and We will leave the code here in case we are able to observe
	// their use in the future (perhaps outside the nft binary debug output).
}

// newBitwiseBool creates a new bitwise boolean operation.
func newBitwiseBool(sreg, dreg uint8, mask, xor []byte) (*bitwise, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise operation does not support verdict register as source or destination register")
	}
	blen := len(mask)
	if blen != len(xor) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation mask and xor data lengths must be the same")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && (is4ByteRegister(sreg) || is4ByteRegister(dreg))) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("bitwise boolean operation cannot use more than %d bytes", linux.NFT_REG_SIZE))
	}
	return &bitwise{sreg: sreg, dreg: dreg, bop: linux.NFT_BITWISE_BOOL, blen: uint8(blen), mask: newBytesData(mask), xor: newBytesData(xor)}, nil
}

// newBitwiseShift creates a new bitwise shift operation.
func newBitwiseShift(sreg, dreg, blen uint8, shift uint32, right bool) (*bitwise, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise shift operation does not support verdict register as source or destination register")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && (is4ByteRegister(sreg) || is4ByteRegister(dreg))) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("bitwise operation length %d is too long for source register %d, destination register %d", blen, sreg, dreg))
	}
	if shift >= bitshiftLimit {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("bitwise operation shift %d must be less than %d", shift, bitshiftLimit))
	}
	bop := bitwiseOp(linux.NFT_BITWISE_LSHIFT)
	if right {
		bop = linux.NFT_BITWISE_RSHIFT
	}
	return &bitwise{sreg: sreg, dreg: dreg, blen: blen, bop: bop, shift: shift}, nil
}

// evaluateBitwiseBool performs the bitwise boolean operation on the source register
// data and stores the result in the destination register.
func evaluateBitwiseBool(sregBuf, dregBuf, mask, xor []byte) {
	for i := 0; i < len(mask); i++ {
		dregBuf[i] = (sregBuf[i] & mask[i]) ^ xor[i]
	}
}

// evaluateBitwiseLshift performs the bitwise left shift operation on source
// register in 4 byte chunks and stores the result in the destination register.
func evaluateBitwiseLshift(sregBuf, dregBuf []byte, shift uint32) {
	carry := uint32(0)

	// Rounds down to nearest 4-byte multiple.
	for start := (len(sregBuf) - 1) & ^3; start >= 0; start -= 4 {
		// Extracts the 4-byte chunk from the source register, padding if necessary.
		var chunk uint32
		if start+4 <= len(sregBuf) {
			chunk = binary.BigEndian.Uint32(sregBuf[start:])
		} else {
			var padded [4]byte
			copy(padded[:], sregBuf[start:])
			chunk = binary.BigEndian.Uint32(padded[:])
		}

		// Does left shift, adds the carry, and calculates the new carry.
		res := (chunk << shift) | carry
		carry = chunk >> (bitshiftLimit - shift)

		// Stores the result in the destination register, using temporary buffer
		// if necessary.
		if start+4 <= len(dregBuf) {
			binary.BigEndian.PutUint32(dregBuf[start:], res)
		} else {
			var padded [4]byte
			binary.BigEndian.PutUint32(padded[:], res)
			copy(dregBuf[start:], padded[:])
		}
	}
}

// evaluateBitwiseRshift performs the bitwise right shift operation on source
// register in 4 byte chunks and stores the result in the destination register.
func evaluateBitwiseRshift(sregBuf, dregBuf []byte, shift uint32) {
	carry := uint32(0)

	for start := 0; start < len(sregBuf); start += 4 {
		// Extracts the 4-byte chunk from the source register, padding if necessary.
		var chunk uint32
		if start+4 <= len(sregBuf) {
			chunk = binary.BigEndian.Uint32(sregBuf[start:])
		} else {
			var padded [4]byte
			copy(padded[:], sregBuf[start:])
			chunk = binary.BigEndian.Uint32(padded[:])
		}

		// Does right shift, adds the carry, and calculates the new carry.
		res := carry | (chunk >> shift)
		carry = chunk << (bitshiftLimit - shift)

		// Stores the result in the destination register, using temporary buffer
		// if necessary.
		if start+4 <= len(dregBuf) {
			binary.BigEndian.PutUint32(dregBuf[start:], res)
		} else {
			var padded [4]byte
			binary.BigEndian.PutUint32(padded[:], res)
			copy(dregBuf[start:], padded[:])
		}
	}
}

// evaluate for bitwise performs the bitwise operation on the source register
// data and stores the result in the destination register.
func (op bitwise) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the specified buffers of the source and destination registers.
	sregBuf := getRegisterBuffer(regs, op.sreg)[:op.blen]
	dregBuf := getRegisterBuffer(regs, op.dreg)[:op.blen]

	if op.bop == linux.NFT_BITWISE_BOOL {
		evaluateBitwiseBool(sregBuf, dregBuf, op.mask.data, op.xor.data)
		return
	}

	if op.bop == linux.NFT_BITWISE_LSHIFT {
		evaluateBitwiseLshift(sregBuf, dregBuf, op.shift)
	} else {
		evaluateBitwiseRshift(sregBuf, dregBuf, op.shift)
	}

}

func (op bitwise) GetExprName() string {
	return "bitwise"
}

// TODO: b/452648112 - Implement dump for bitwise operation.
func (op bitwise) Dump() ([]byte, *syserr.AnnotatedError) {
	log.Warningf("Nftables: Dumping bitwise operation is not implemented")
	return nil, nil
}
