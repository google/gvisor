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
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// immediate is an operation that sets the data in a register.
type immediate struct {
	dregIdx  int             // Index of the destination register in registerSet.data.
	dataType uint32          // Type of data in the register (NFT_DATA_VALUE or NFT_DATA_VERDICT).
	data     []byte          // optional
	verdict  stack.NFVerdict // optional
}

// evaluate for immediate sets the data in the destination register.
func (op immediate) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	switch op.dataType {
	case linux.NFT_DATA_VALUE:
		copy(regs.data[op.dregIdx:], op.data)
	case linux.NFT_DATA_VERDICT:
		regs.verdict = op.verdict
	}
}

func (op immediate) GetExprName() string {
	return OpTypeImmediate.String()
}

func (op immediate) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	var regDump []byte
	var err *syserr.AnnotatedError
	reg := uint32(0)
	switch op.dataType {
	case linux.NFT_DATA_VERDICT:
		regDump, err = dumpVerdictDataAttr(op.verdict)
	case linux.NFT_DATA_VALUE:
		reg = uint32(formatRegIdxForDump(op.dregIdx))
		regDump, err = dumpDataAttr(op.data)
	}
	if err != nil {
		return nil, err
	}
	m.PutAttr(linux.NFTA_IMMEDIATE_DREG, nlmsg.PutU32(reg))
	m.PutAttr(linux.NFTA_IMMEDIATE_DATA, primitive.AsByteSlice(regDump))
	return m.Buffer(), nil
}

// newImmediate creates a new immediate operation.
func newImmediate(dreg uint8, dataType uint32, data []byte, verdict stack.NFVerdict) (*immediate, *syserr.AnnotatedError) {
	switch dataType {
	case linux.NFT_DATA_VALUE:
		dregIdx, err := regNumToIdx(dreg, len(data))
		if err != nil {
			return nil, err
		}
		return &immediate{dregIdx: dregIdx, dataType: dataType, data: data}, nil
	case linux.NFT_DATA_VERDICT:
		return &immediate{dataType: dataType, verdict: verdict}, nil
	}
	return nil, syserr.NewAnnotatedError(syserr.ErrRange, "Nftables: NFTA_IMMEDIATE_DATA is not a valid data type")
}

// InitImmediate initializes the immediate operation from the expression info.
func initImmediate(tab *Table, exprInfo ExprInfo) (*immediate, *syserr.AnnotatedError) {
	// We now have attributes specific to immediate expressions.
	immDataAttrs, ok := NfParse(exprInfo.ExprData)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse immediate expression data")
	}

	reg, ok := AttrNetToHost[uint32](linux.NFTA_IMMEDIATE_DREG, immDataAttrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_IMMEDIATE_DREG attribute is not found")
	}
	dataBytes, ok := immDataAttrs[linux.NFTA_IMMEDIATE_DATA]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_IMMEDIATE_DATA attribute is not found")
	}
	dataAttrs, ok := NfParse(nlmsg.AttrsView(dataBytes))
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse data bytes for nested expression data")
	}

	regType := immRegToType(reg)
	if regType == linux.NFT_DATA_VERDICT {
		verdict, err := parseVerdictAttrs(tab, dataAttrs)
		if err != nil {
			return nil, err
		}
		return newImmediate(linux.NFT_REG_VERDICT /* dreg */, regType, nil /* data */, verdict)
	}
	// Data register.
	data, err := parseDataAttrs(dataAttrs)
	if err != nil {
		return nil, err
	}
	return newImmediate(uint8(reg), regType, data, stack.NFVerdict{})
}

// immRegToType returns the corresponding data type for a given register number.
// Assumes that the value is in host byte order.
func immRegToType(reg uint32) uint32 {
	if reg == linux.NFT_REG_VERDICT {
		return linux.NFT_DATA_VERDICT
	}
	return linux.NFT_DATA_VALUE
}
