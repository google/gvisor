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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// immediate is an operation that sets the data in a register.
type immediate struct {
	data registerData // Data to set the destination register to.
	dreg uint8        // Number of the destination register.
}

// evaluate for immediate sets the data in the destination register.
func (op immediate) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	op.data.storeData(regs, op.dreg)
}

// newImmediate creates a new immediate operation.
func newImmediate(dreg uint8, data registerData) (*immediate, *syserr.AnnotatedError) {
	if err := data.validateRegister(dreg); err != nil {
		return nil, err
	}
	return &immediate{dreg: dreg, data: data}, nil
}

// InitImmediate initializes the immediate operation from the expression info.
func initImmediate(tab *Table, exprInfo ExprInfo) (*immediate, *syserr.AnnotatedError) {
	// We now have attributes specific to immediate expressions.
	immDataAttrs, ok := NfParse(exprInfo.ExprData)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse immediate expression data")
	}

	regBytes, ok := immDataAttrs[linux.NFTA_IMMEDIATE_DREG]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_IMMEDIATE_DREG attribute is not found")
	}

	reg, ok := regBytes.Uint32()
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_IMMEDIATE_DREG attribute is malformed")
	}

	reg = nlmsg.NetToHostU32(reg)
	dataBytes, ok := immDataAttrs[linux.NFTA_IMMEDIATE_DATA]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_IMMEDIATE_DATA attribute is not found")
	}

	dregType := immRegToType(reg)
	regData, err := nftDataInit(tab, dregType, nlmsg.AttrsView(dataBytes))
	if err != nil {
		return nil, err
	}

	// Now find the register to store it in.
	dreg, err := nftParseReg(reg, dregType, regData)
	if err != nil {
		return nil, err
	}

	switch int32(dreg) {
	case linux.NFT_JUMP, linux.NFT_GOTO:
		// TODO - b/434244017: Add support for jump and goto verdicts.
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Verdicts with jump or goto codes are not yet supported")
	}
	return newImmediate(dreg, regData)
}

// immRegToType returns the corresponding data type for a given register number.
// Assumes that the value is in host byte order.
func immRegToType(reg uint32) uint32 {
	if reg == linux.NFT_REG_VERDICT {
		return linux.NFT_DATA_VERDICT
	}

	return linux.NFT_DATA_VALUE
}
