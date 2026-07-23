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
	"math"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
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
	sregIdx int       // Index of the source register in registerSet.data.
	dregIdx int       // Index of the destination register in registerSet.data.
	bop     bitwiseOp // Bitwise operator to use.
	blen    int       // Number of bytes to apply bitwise operation to.
	mask    []byte    // Mask to apply bitwise & for boolean operations (before ^).
	xor     []byte    // Xor to apply bitwise ^ for boolean operations (after &).
	shift   uint32    // Shift to apply bitwise <</>> for non-boolean operations.

	// Note: Technically, the linux kernel has defined bool, lshift, and rshift
	// as the 3 types of bitwise operations. However, we have not been able to
	// observe the lshift or rshift operations used by the nft binary. Thus, we
	// have no way to test the interpretation of these operations. Maintaining
	// consistency with the linux kernel, we have fully implemented lshift and
	// rshift, and We will leave the code here in case we are able to observe
	// their use in the future (perhaps outside the nft binary debug output).
}

// newBitwiseBool creates a new bitwise boolean operation.
func newBitwiseBool(sreg, dreg uint8, mask, xor []byte, blen int) (*bitwise, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise operation does not support verdict register as source or destination register")
	}
	l := len(mask)
	if l != len(xor) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation mask and xor data lengths must be the same")
	}
	if l != blen {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation invalid length")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && (is4ByteRegister(sreg) || is4ByteRegister(dreg))) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation invalid length")
	}
	var err *syserr.AnnotatedError
	var sregIdx, dregIdx int
	if sregIdx, err = regNumToIdx(sreg, blen); err != nil {
		return nil, err
	}
	if dregIdx, err = regNumToIdx(dreg, blen); err != nil {
		return nil, err
	}
	return &bitwise{sregIdx: sregIdx, dregIdx: dregIdx, bop: linux.NFT_BITWISE_BOOL, blen: blen, mask: mask[:blen], xor: xor[:blen]}, nil
}

// newBitwiseShift creates a new bitwise shift operation.
func newBitwiseShift(sreg, dreg uint8, blen int, shift uint32, right bool) (*bitwise, *syserr.AnnotatedError) {
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
	var err *syserr.AnnotatedError
	var sregIdx, dregIdx int
	if sregIdx, err = regNumToIdx(sreg, int(blen)); err != nil {
		return nil, err
	}
	if dregIdx, err = regNumToIdx(dreg, int(blen)); err != nil {
		return nil, err
	}
	return &bitwise{sregIdx: sregIdx, dregIdx: dregIdx, blen: blen, bop: bop, shift: shift}, nil
}

func (op *bitwise) deepCopy() operation {
	opCopy := *op
	opCopy.mask = slices.Clone(op.mask)
	opCopy.xor = slices.Clone(op.xor)
	return &opCopy
}

// updateReferences implements operation.updateReferences.
func (op *bitwise) updateReferences(table *Table, sourceTable *Table, sourceOp operation) {}

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
			chunk = binary.NativeEndian.Uint32(sregBuf[start:])
		} else {
			var padded [4]byte
			copy(padded[:], sregBuf[start:])
			chunk = binary.NativeEndian.Uint32(padded[:])
		}

		// Does left shift, adds the carry, and calculates the new carry.
		res := (chunk << shift) | carry
		carry = chunk >> (bitshiftLimit - shift)

		// Stores the result in the destination register, using temporary buffer
		// if necessary.
		if start+4 <= len(dregBuf) {
			binary.NativeEndian.PutUint32(dregBuf[start:], res)
		} else {
			var padded [4]byte
			binary.NativeEndian.PutUint32(padded[:], res)
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
			chunk = binary.NativeEndian.Uint32(sregBuf[start:])
		} else {
			var padded [4]byte
			copy(padded[:], sregBuf[start:])
			chunk = binary.NativeEndian.Uint32(padded[:])
		}

		// Does right shift, adds the carry, and calculates the new carry.
		res := carry | (chunk >> shift)
		carry = chunk << (bitshiftLimit - shift)

		// Stores the result in the destination register, using temporary buffer
		// if necessary.
		if start+4 <= len(dregBuf) {
			binary.NativeEndian.PutUint32(dregBuf[start:], res)
		} else {
			var padded [4]byte
			binary.NativeEndian.PutUint32(padded[:], res)
			copy(dregBuf[start:], padded[:])
		}
	}
}

// evaluate for bitwise performs the bitwise operation on the source register
// data and stores the result in the destination register.
func (op bitwise) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	// Gets the specified buffers of the source and destination registers.
	sregBuf := regs.data[op.sregIdx : op.sregIdx+op.blen]
	dregBuf := regs.data[op.dregIdx : op.dregIdx+op.blen]

	if op.bop == linux.NFT_BITWISE_BOOL {
		evaluateBitwiseBool(sregBuf, dregBuf, op.mask, op.xor)
		return
	}

	if op.bop == linux.NFT_BITWISE_LSHIFT {
		evaluateBitwiseLshift(sregBuf, dregBuf, op.shift)
	} else {
		evaluateBitwiseRshift(sregBuf, dregBuf, op.shift)
	}
}

func (op bitwise) GetExprName() string {
	return OpTypeBitwise.String()
}

func (op bitwise) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_BITWISE_SREG, formatRegIdxForDump(op.sregIdx))
	m.PutAttr(linux.NFTA_BITWISE_DREG, formatRegIdxForDump(op.dregIdx))
	m.PutAttr(linux.NFTA_BITWISE_LEN, nlmsg.PutU32(uint32(op.blen)))
	m.PutAttr(linux.NFTA_BITWISE_OP, nlmsg.PutU32(uint32(op.bop)))

	switch op.bop {
	case linux.NFT_BITWISE_BOOL:
		maskDump, err := dumpDataAttr(op.mask)
		if err != nil {
			return nil, err
		}
		m.PutAttr(linux.NFTA_BITWISE_MASK, primitive.AsByteSlice(maskDump))

		xorDump, err := dumpDataAttr(op.xor)
		if err != nil {
			return nil, err
		}
		m.PutAttr(linux.NFTA_BITWISE_XOR, primitive.AsByteSlice(xorDump))
	case linux.NFT_BITWISE_LSHIFT, linux.NFT_BITWISE_RSHIFT:
		shiftData := make([]byte, 4)
		binary.NativeEndian.PutUint32(shiftData, op.shift)
		dataDump, err := dumpDataAttr(shiftData)
		if err != nil {
			return nil, err
		}
		m.PutAttr(linux.NFTA_BITWISE_DATA, primitive.AsByteSlice(dataDump))
	}

	return m.Buffer(), nil
}

// checkCompatibility implements operation.checkCompatibility.
func (op bitwise) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

// initBitwiseBool initializes a bitwise boolean operation.
// Ref: net/netfilter/nft_bitwise.c:nft_bitwise_init_bool()
func initBitwiseBool(maskAttrBytes, xorAttrBytes nlmsg.BytesView, l uint32, sreg, dreg uint8) (*bitwise, *syserr.AnnotatedError) {
	maskAttrs, ok := NfParse(nlmsg.AttrsView(maskAttrBytes))
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise boolean operation mask attribute")
	}
	mask, err := parseDataAttrs(maskAttrs)
	if err != nil {
		return nil, err
	}
	xorAttrs, ok := NfParse(nlmsg.AttrsView(xorAttrBytes))
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise boolean operation xor attribute")
	}
	xor, err := parseDataAttrs(xorAttrs)
	if err != nil {
		return nil, err
	}

	return newBitwiseBool(uint8(sreg), uint8(dreg), mask, xor, int(l))
}

// initBitwiseShift initializes a bitwise shift operation.
// Ref: net/netfilter/nft_bitwise.c:nft_bitwise_init_shift()
func initBitwiseShift(dataAttrBytes nlmsg.BytesView, l uint32, sreg, dreg uint8, bitwiseOp uint32) (*bitwise, *syserr.AnnotatedError) {
	dataAttrs, ok := NfParse(nlmsg.AttrsView(dataAttrBytes))
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise shift operation data attribute")
	}
	shiftData, err := parseDataAttrs(dataAttrs)
	if err != nil {
		return nil, err
	}
	if len(shiftData) != 4 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise shift operation data length must be 4 bytes")
	}
	shift := binary.NativeEndian.Uint32(shiftData[:4])
	return newBitwiseShift(uint8(sreg), uint8(dreg), int(l), shift, bitwiseOp == linux.NFT_BITWISE_RSHIFT)
}

// bitwiseAttrPolicy is the policy for parsing the attributes of a bitwise operation.
// Ref: net/netfilter/nft_bitwise.c:nft_bitwise_policy
var bitwiseAttrPolicy = []NlaPolicy{
	linux.NFTA_BITWISE_SREG: {nlaType: linux.NLA_U32},
	linux.NFTA_BITWISE_DREG: {nlaType: linux.NLA_U32},
	linux.NFTA_BITWISE_LEN:  {nlaType: linux.NLA_U32},
	linux.NFTA_BITWISE_MASK: {nlaType: linux.NLA_NESTED},
	linux.NFTA_BITWISE_XOR:  {nlaType: linux.NLA_NESTED},
	linux.NFTA_BITWISE_OP:   NlaPolicy{nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](math.MaxUint8)},
	linux.NFTA_BITWISE_DATA: {nlaType: linux.NLA_NESTED},
}

// initBitwise initializes a bitwise operation.
// Ref: net/netfilter/nft_bitwise.c:nft_bitwise_init()
func initBitwise(tab *Table, exprInfo ExprInfo) (*bitwise, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: bitwiseAttrPolicy,
	})
	if err != nil {
		return nil, err
	}

	blen, ok := AttrNetToHost[uint32](linux.NFTA_BITWISE_LEN, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise expression data length")
	}

	sreg, ok := AttrNetToHost[uint32](linux.NFTA_BITWISE_SREG, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise expression source register")
	}

	dreg, ok := AttrNetToHost[uint32](linux.NFTA_BITWISE_DREG, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise expression destination register")
	}

	bitwiseOp, ok := AttrNetToHost[uint32](linux.NFTA_BITWISE_OP, attrs)
	if !ok {
		bitwiseOp = uint32(linux.NFT_BITWISE_BOOL)
	} else {
		switch int(bitwiseOp) {
		case linux.NFT_BITWISE_BOOL, linux.NFT_BITWISE_LSHIFT, linux.NFT_BITWISE_RSHIFT:
		default:
			return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "unsupported bitwise operation")
		}
	}

	data, dataOk := attrs[linux.NFTA_BITWISE_DATA]
	mask, maskOk := attrs[linux.NFTA_BITWISE_MASK]
	xor, xorOk := attrs[linux.NFTA_BITWISE_XOR]

	if bitwiseOp == linux.NFT_BITWISE_BOOL {
		if dataOk {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation cannot use data attribute")
		}

		if !maskOk {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation mask attribute is missing")
		}
		if !xorOk {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise boolean operation xor attribute is missing")
		}
		return initBitwiseBool(mask, xor, blen, uint8(sreg), uint8(dreg))
	}

	if bitwiseOp == linux.NFT_BITWISE_LSHIFT || bitwiseOp == linux.NFT_BITWISE_RSHIFT {
		if maskOk || xorOk {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise shift operation cannot use mask or xor attribute")
		}
		if !dataOk {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "bitwise shift operation data attribute is missing")
		}
		return initBitwiseShift(data, blen, uint8(sreg), uint8(dreg), bitwiseOp)
	}
	return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse bitwise expression operation")
}
