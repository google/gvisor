// Copyright 2025 The gVisor Authors.
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

// byteorder is an operation that performs byte order operations on a register.
// Note: byteorder operations are not supported for the verdict register.
type byteorder struct {
	sreg uint8       // Number of the source register.
	dreg uint8       // Number of the destination register.
	bop  byteorderOp // Byte order operation to perform.
	blen uint8       // Number of total bytes to operate on.
	size uint8       // Granular size in bytes to operate on.
}

// byteorderOp is the byte order operator for a byteorder operation.
// Note: corresponds to enum nft_byteorder_ops from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type byteorderOp int

// byteorderOpStrings is a map of byteorder operator to its string
// representation.
var byteorderOpStrings = map[byteorderOp]string{
	linux.NFT_BYTEORDER_NTOH: "network to host",
	linux.NFT_BYTEORDER_HTON: "host to network",
}

// String for byteorderOp returns the string representation of the byteorder
// operator.
func (bop byteorderOp) String() string {
	if bopStr, ok := byteorderOpStrings[bop]; ok {
		return bopStr
	}
	panic(fmt.Sprintf("invalid byteorder operator: %d", int(bop)))
}

// validateByteorderOp ensures the byteorder operator is valid.
func validateByteorderOp(bop byteorderOp) *syserr.AnnotatedError {
	switch bop {
	// Supported operators.
	case linux.NFT_BYTEORDER_NTOH, linux.NFT_BYTEORDER_HTON:
		return nil
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid byteorder operator: %d", int(bop)))
	}
}

// newByteorder creates a new byteorder operation.
func newByteorder(sreg, dreg uint8, bop byteorderOp, blen, size uint8) (*byteorder, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "byteorder operation does not support verdict register as source or destination register")
	}
	if err := validateByteorderOp(bop); err != nil {
		return nil, err
	}
	if blen > linux.NFT_REG_SIZE {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("byteorder operation cannot use more than %d bytes", linux.NFT_REG_SIZE))
	}
	if (is4ByteRegister(sreg) || is4ByteRegister(dreg)) && blen > linux.NFT_REG32_SIZE {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("byteorder operation cannot use more than %d bytes", linux.NFT_REG32_SIZE))
	}
	if size > blen {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("byteorder operation cannot use more than %d bytes", blen))
	}
	if size != 2 && size != 4 && size != 8 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("byteorder operation size %d is not supported", size))
	}
	return &byteorder{sreg: sreg, dreg: dreg, bop: bop, blen: blen, size: size}, nil
}

// evaluate for byteorder performs the byte order operation on the source
// register and stores the result in the destination register.
func (op byteorder) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the source and destination registers.
	src := getRegisterBuffer(regs, op.sreg)
	dst := getRegisterBuffer(regs, op.dreg)

	// Performs the byte order operations on the source register and stores the
	// result in as many bytes as are available in the destination register.
	switch op.size {
	case 8:
		switch op.bop {
		case linux.NFT_BYTEORDER_NTOH:
			for i := uint8(0); i < op.blen; i += 8 {
				networkNum := binary.BigEndian.Uint64(src[i : i+8])
				binary.NativeEndian.PutUint64(dst[i:], networkNum)
			}
		case linux.NFT_BYTEORDER_HTON:
			for i := uint8(0); i < op.blen; i += 8 {
				hostNum := binary.NativeEndian.Uint64(src[i : i+8])
				binary.BigEndian.PutUint64(dst[i:], hostNum)
			}
		}

	case 4:
		switch op.bop {
		case linux.NFT_BYTEORDER_NTOH:
			for i := uint8(0); i < op.blen; i += 4 {
				networkNum := binary.BigEndian.Uint32(src[i : i+4])
				binary.NativeEndian.PutUint32(dst[i:], networkNum)
			}
		case linux.NFT_BYTEORDER_HTON:
			for i := uint8(0); i < op.blen; i += 4 {
				hostNum := binary.NativeEndian.Uint32(src[i : i+4])
				binary.BigEndian.PutUint32(dst[i:], hostNum)
			}
		}

	case 2:
		switch op.bop {
		case linux.NFT_BYTEORDER_NTOH:
			for i := uint8(0); i < op.blen; i += 2 {
				networkNum := binary.BigEndian.Uint16(src[i : i+2])
				binary.NativeEndian.PutUint16(dst[i:], networkNum)
			}
		case linux.NFT_BYTEORDER_HTON:
			for i := uint8(0); i < op.blen; i += 2 {
				hostNum := binary.NativeEndian.Uint16(src[i : i+2])
				binary.BigEndian.PutUint16(dst[i:], hostNum)
			}
		}
	}

	// Zeroes out excess bytes of the destination register.
	// This is done since comparison can be done in multiples of 4 bytes.
	if rem := op.blen % 4; rem != 0 {
		clear(dst[op.blen : op.blen+4-rem])
	}
}

func (op byteorder) GetExprName() string {
	return "byteorder"
}

// TODO: b/452648112 - Implement dump for last operation.
func (op byteorder) Dump() ([]byte, *syserr.AnnotatedError) {
	log.Warningf("Nftables: Dumping byteorder operation is not implemented")
	return nil, nil
}
