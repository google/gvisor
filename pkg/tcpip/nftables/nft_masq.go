// Copyright 2026 The gVisor Authors.
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

package nftables

import (
	"encoding/binary"
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// masqOp corresponds to the NFT_MASQ expression.
type masqOp struct {
	// Index of the source register for the minimum protocol in the register set.
	sregProtoMinIdx int8
	// Index of the source register for the maximum protocol in the register set.
	sregProtoMaxIdx int8
	// Flags for the NAT operation.
	flags uint32
}

// newMasqOp creates a new masquerade operation.
func newMasqOp(sregProtoMin, sregProtoMax int, flags uint32) (*masqOp, *syserr.AnnotatedError) {
	const unsetReg = -1
	regIdxOrDefault := func(reg int, len int, defaultIdx int8) (int8, *syserr.AnnotatedError) {
		if reg == unsetReg {
			return defaultIdx, nil
		}
		v, err := regNumToIdx(uint8(reg), len)
		if err != nil {
			return -1, err
		}
		return int8(v), nil
	}

	masq := &masqOp{
		flags: flags,
	}
	len := linux.SizeOfNfConntrackManProto
	var err *syserr.AnnotatedError
	if masq.sregProtoMinIdx, err = regIdxOrDefault(sregProtoMin, len, unsetReg); err != nil {
		return nil, err
	}

	// Proto max defaults to min if not set.
	if masq.sregProtoMaxIdx, err = regIdxOrDefault(sregProtoMax, len, masq.sregProtoMinIdx); err != nil {
		return nil, err
	}
	return masq, nil
}

// targetPortRangeForTCPAndUDP returns the default port range for TCP/UDP masquerade.
// TODO: b/486197011 - Unify this function with
// the iptables_targets.go:targetPortRangeForTCPAndUDP.
func targetPortRangeForTCPAndUDP(originalSrcPort uint16) stack.PortOrIdentRange {
	switch {
	case originalSrcPort < 512:
		return stack.PortOrIdentRange{Start: 1, Size: 511}
	case originalSrcPort < 1024:
		return stack.PortOrIdentRange{Start: 600, Size: 1023}
	default:
		return stack.PortOrIdentRange{Start: 1024, Size: math.MaxUint16 - 1023}
	}
}

// evaluate implements operation.evaluate.
// Ref: net/netfilter/nft_masq.c:nft_masq_eval()
func (m *masqOp) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	pkt := evalCtx.pkt
	changePort := false
	var minProto, maxProto uint32
	if m.sregProtoMinIdx >= 0 {
		changePort = true
		regBuffer := regs.data
		minBuf := regBuffer[m.sregProtoMinIdx : m.sregProtoMinIdx+2]
		minProto = uint32(binary.BigEndian.Uint16(minBuf))
		maxBuf := regBuffer[m.sregProtoMaxIdx : m.sregProtoMaxIdx+2]
		maxProto = uint32(binary.BigEndian.Uint16(maxBuf))
	}

	var ports stack.PortOrIdentRange
	if changePort {
		ports = stack.PortOrIdentRange{
			Start: uint16(minProto),
			Size:  maxProto - minProto + 1,
		}
	} else {
		// Fallback to default port range handling if not specified.
		switch pkt.TransportProtocolNumber {
		case header.UDPProtocolNumber:
			ports = targetPortRangeForTCPAndUDP(header.UDP(pkt.TransportHeader().Slice()).SourcePort())
		case header.TCPProtocolNumber:
			ports = targetPortRangeForTCPAndUDP(header.TCP(pkt.TransportHeader().Slice()).SourcePort())
		case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
			ports = stack.PortOrIdentRange{Start: 0, Size: math.MaxUint16 + 1}
		}
		// We want to change port to the selected range even if not specified in expr.
		changePort = true
	}

	// Configure NAT for the packet to change the source address.
	if !pkt.ConfigureMasquerade(ports, evalCtx.route, evalCtx.nftState.stack, changePort) {
		regs.verdict.Code = VC(linux.NF_DROP)
		return
	}

	regs.verdict.Code = VC(linux.NF_ACCEPT)
}

// GetExprName implements operation.GetExprName.
func (m *masqOp) GetExprName() string {
	return OpTypeMasq.String()
}

// deepCopy implements operation.deepCopy.
func (m *masqOp) deepCopy() operation {
	opCopy := *m
	return &opCopy
}

// Dump implements operation.Dump.
func (m *masqOp) Dump() ([]byte, *syserr.AnnotatedError) {
	msg := &nlmsg.Message{}
	if m.flags != 0 {
		msg.PutAttr(linux.NFTA_MASQ_FLAGS, nlmsg.PutU32(nlmsg.HostToNetU32(m.flags)))
	}
	if m.sregProtoMinIdx >= 0 {
		msg.PutAttr(linux.NFTA_MASQ_REG_PROTO_MIN, formatRegIdxForDump(int(m.sregProtoMinIdx)))
		msg.PutAttr(linux.NFTA_MASQ_REG_PROTO_MAX, formatRegIdxForDump(int(m.sregProtoMaxIdx)))
	}
	return msg.Buffer(), nil
}

// checkCompatibility ensures that the masquerade operation is used in a valid chain.
// Ref: net/netfilter/nft_masq.c:nft_masq_validate()
func (m *masqOp) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	chain := cCtx.chain
	if !chain.IsBaseChain() {
		return nil
	}
	if chain.baseChainInfo.Hook != stack.NFPostrouting {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "masq expression is only valid in postrouting hook")
	}
	if chain.baseChainInfo.BcType != BaseChainTypeNat {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "masq expression is only valid in NAT chains")
	}
	return nil
}

// Ref: net/netfilter/nft_masq.c:nft_masq_policy
var masqAttrPolicy = []NlaPolicy{
	linux.NFTA_MASQ_FLAGS:         {nlaType: linux.NLA_BE32, validator: AttrMaskValidator[uint32](linux.NF_NAT_RANGE_MASK)},
	linux.NFTA_MASQ_REG_PROTO_MIN: {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_MASQ_REG_PROTO_MAX: {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
}

// initMasqOp initializes a masquerade operation from the given expression information.
// Ref: net/netfilter/nft_masq.c:nft_masq_init()
func initMasqOp(tab *Table, exprInfo ExprInfo) (*masqOp, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: masqAttrPolicy,
	})
	if err != nil {
		return nil, err
	}

	// Use flag value as `0` if not set; so the err can be ignored here.
	flags, _ := AttrNetToHost[uint32](linux.NFTA_MASQ_FLAGS, attrs)
	regProtoMin, regProtoMinOk := AttrNetToHost[uint32](linux.NFTA_MASQ_REG_PROTO_MIN, attrs)

	sregProtoMin, sregProtoMax := -1, -1
	if regProtoMinOk {
		sregProtoMin = int(regProtoMin)
		regProtoMax, regProtoMaxOk := AttrNetToHost[uint32](linux.NFTA_MASQ_REG_PROTO_MAX, attrs)
		if !regProtoMaxOk {
			sregProtoMax = sregProtoMin
		} else {
			sregProtoMax = int(regProtoMax)
		}
	}

	return newMasqOp(sregProtoMin, sregProtoMax, flags)
}
