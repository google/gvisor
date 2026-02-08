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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ranged is an operation that checks whether the data in a register is between
// an inclusive range and breaks if the comparison is false.
// Note: ranged operations are not supported for the verdict register.
// Note: named "ranged" because "range" is a reserved keyword in Go.
type ranged struct {
	low  bytesData // Data to compare the source register to.
	high bytesData // Data to compare the source register to.
	sreg uint8     // Number of the source register.
	rop  rngOp     // Range operator.

	// Note: The linux kernel defines the range operation, but we have not been
	// able to observe it used by the nft binary. For any commands that may use
	// range, the nft binary seems to use two comparison operations instead. Thus,
	// there is no interpretation of the range operation via the nft binary debug
	// output, but the operation is fully supported and implemented.
}

// rngOp is the range operator for a Ranged operation.
// Note: corresponds to enum nft_range_ops from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type rngOp int

// rngOpStrings is a map of rngOp to its string representation.
var rngOpStrings = map[rngOp]string{
	linux.NFT_RANGE_EQ:  "range ==",
	linux.NFT_RANGE_NEQ: "range !=",
}

// String for rngOp returns string representation of the range operator.
func (rop rngOp) String() string {
	if ropStr, ok := rngOpStrings[rop]; ok {
		return ropStr
	}
	panic(fmt.Sprintf("invalid range operator: %d", int(rop)))
}

// validateRangeOp ensures the range operator is valid.
func validateRangeOp(rop rngOp) *syserr.AnnotatedError {
	switch rop {
	case linux.NFT_RANGE_EQ, linux.NFT_RANGE_NEQ:
		return nil
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown range operator: %d", int(rop)))
	}
}

// newRanged creates a new ranged operation.
func newRanged(sreg uint8, op int, low, high []byte) (*ranged, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "ranged operation does not support verdict register as source register")
	}
	if len(low) != len(high) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "upper and lower bounds for ranged operation must be the same length")
	}
	lowData := newBytesData(low)
	if err := lowData.validateRegister(sreg); err != nil {
		return nil, err
	}
	highData := newBytesData(high)
	if err := highData.validateRegister(sreg); err != nil {
		return nil, err
	}
	rop := rngOp(op)
	if err := validateRangeOp(rop); err != nil {
		return nil, err
	}
	return &ranged{sreg: sreg, rop: rop, low: lowData, high: highData}, nil
}

// evaluate for Ranged checks whether the source register data is within the
// specified inclusive range and breaks from the rule if comparison is false.
func (op ranged) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the upper and lower bounds as bytesData.
	low, high := op.low.data, op.high.data

	// Gets the data from the source register.
	regBuf := getRegisterBuffer(regs, op.sreg)[:len(low)]

	// Compares register data to both lower and upper bounds.
	d1 := bytes.Compare(regBuf, low)
	d2 := bytes.Compare(regBuf, high)

	// Determines the comparison result depending on the operator.
	if (d1 >= 0 && d2 <= 0) != (op.rop == linux.NFT_RANGE_EQ) {
		// Comparison is false, so break from the rule.
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
	}
}

func (op ranged) GetExprName() string {
	return "ranged"
}

// TODO: b/452648112 - Implement dump for ranged operation.
func (op ranged) Dump() ([]byte, *syserr.AnnotatedError) {
	log.Warningf("Nftables: Dumping ranged operation is not implemented")
	return nil, nil
}
