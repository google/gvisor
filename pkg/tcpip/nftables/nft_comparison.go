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
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// comparison is an operation that compares the data in a register to a given
// value and breaks (by setting the verdict register to NFT_BREAK) from the rule
// if the comparison is false.
// Note: comparison operations are not supported for the verdict register.
type comparison struct {
	data bytesData // Data to compare the source register to.
	sreg uint8     // Number of the source register.
	cop  cmpOp     // Comparison operator.
}

// cmpOp is the comparison operator for a Comparison operation.
// Note: corresponds to enum nft_cmp_op from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type cmpOp int

// cmpOpStrings is a map of cmpOp to its string representation.
var cmpOpStrings = map[cmpOp]string{
	linux.NFT_CMP_EQ:  "==",
	linux.NFT_CMP_NEQ: "!=",
	linux.NFT_CMP_LT:  "<",
	linux.NFT_CMP_LTE: "<=",
	linux.NFT_CMP_GT:  ">",
	linux.NFT_CMP_GTE: ">=",
}

// String for cmpOp returns string representation of the comparison operator.
func (cop cmpOp) String() string {
	if copStr, ok := cmpOpStrings[cop]; ok {
		return copStr
	}
	panic(fmt.Sprintf("invalid comparison operator: %d", int(cop)))
}

// validateComparisonOp ensures the comparison operator is valid.
func validateComparisonOp(cop cmpOp) *syserr.AnnotatedError {
	switch cop {
	case linux.NFT_CMP_EQ, linux.NFT_CMP_NEQ, linux.NFT_CMP_LT, linux.NFT_CMP_LTE, linux.NFT_CMP_GT, linux.NFT_CMP_GTE:
		return nil
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid comparison operator: %d", int(cop)))
	}
}

// newComparison creates a new comparison operation.
func newComparison(sreg uint8, op int, data []byte) (*comparison, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("comparison operation does not support verdict register as source register"))
	}
	bytesData := newBytesData(data)
	if err := bytesData.validateRegister(sreg); err != nil {
		return nil, err
	}
	cop := cmpOp(op)
	if err := validateComparisonOp(cop); err != nil {
		return nil, err
	}
	return &comparison{sreg: sreg, cop: cop, data: bytesData}, nil
}

// evaluate for Comparison compares the data in the source register to the given
// data and breaks from the rule if the comparison is false.
func (op comparison) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the data to compare to.
	data := op.data.data

	// Gets the data from the source register.
	regBuf := getRegisterBuffer(regs, op.sreg)[:len(data)]

	// Compares bytes from left to right for all bytes in the comparison data.
	dif := bytes.Compare(regBuf, data)

	// Determines the comparison result depending on the operator.
	var result bool
	switch op.cop {
	case linux.NFT_CMP_EQ:
		result = dif == 0
	case linux.NFT_CMP_NEQ:
		result = dif != 0
	case linux.NFT_CMP_LT:
		result = dif < 0
	case linux.NFT_CMP_LTE:
		result = dif <= 0
	case linux.NFT_CMP_GT:
		result = dif > 0
	case linux.NFT_CMP_GTE:
		result = dif >= 0
	}
	if !result {
		// Comparison is false, so break from the rule.
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
	}
}
