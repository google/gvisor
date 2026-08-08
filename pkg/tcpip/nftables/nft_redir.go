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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// redirOp corresponds to the NFT_REDIR expression. It redirects packets to the
// local machine - loopback in the output hook, the incoming interface's primary
// address in prerouting - optionally rewriting the destination port to a range
// taken from a register. It is a special case of destination NAT.
// Ref: net/netfilter/nft_redir.c
type redirOp struct {
	// Index of the source register for the minimum port in the register set.
	sregProtoMinIdx int8
	// Index of the source register for the maximum port in the register set.
	sregProtoMaxIdx int8
	// Flags for the NAT operation.
	flags uint32
}

// newRedirOp creates a new redirect operation.
func newRedirOp(sregProtoMin, sregProtoMax int, flags uint32) (*redirOp, *syserr.AnnotatedError) {
	const unsetReg = -1
	regIdxOrDefault := func(reg, length int, defaultIdx int8) (int8, *syserr.AnnotatedError) {
		if reg == unsetReg {
			return defaultIdx, nil
		}
		v, err := regNumToIdx(uint8(reg), length)
		if err != nil {
			return -1, err
		}
		return int8(v), nil
	}

	rd := &redirOp{flags: flags}
	length := linux.SizeOfNfConntrackManProto
	var err *syserr.AnnotatedError
	if rd.sregProtoMinIdx, err = regIdxOrDefault(sregProtoMin, length, unsetReg); err != nil {
		return nil, err
	}
	// Proto max defaults to min if not set.
	if rd.sregProtoMaxIdx, err = regIdxOrDefault(sregProtoMax, length, rd.sregProtoMinIdx); err != nil {
		return nil, err
	}
	return rd, nil
}

// evaluate implements operation.evaluate.
// Ref: net/netfilter/nft_redir.c:nft_redir_eval()
func (rd *redirOp) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	pkt := evalCtx.pkt

	// Redirect destination: loopback in output, the incoming interface's
	// primary address in prerouting (mirrors stack.RedirectTarget).
	var addr tcpip.Address
	switch evalCtx.hook {
	case stack.NFOutput:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			addr = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
		} else {
			addr = header.IPv6Loopback
		}
	case stack.NFPrerouting:
		nicAddr, err := evalCtx.nftState.stack.GetMainNICAddress(pkt.InputNICID, pkt.NetworkProtocolNumber)
		if err != nil {
			regs.verdict.Code = VC(linux.NF_DROP)
			return
		}
		addr = nicAddr.Address
	default:
		regs.verdict.Code = VC(linux.NF_DROP)
		return
	}

	changePort := false
	var minProto, maxProto uint32
	if rd.sregProtoMinIdx >= 0 {
		changePort = true
		regBuffer := regs.data
		minBuf := regBuffer[rd.sregProtoMinIdx : rd.sregProtoMinIdx+2]
		minProto = uint32(binary.BigEndian.Uint16(minBuf))
		maxBuf := regBuffer[rd.sregProtoMaxIdx : rd.sregProtoMaxIdx+2]
		maxProto = uint32(binary.BigEndian.Uint16(maxBuf))
	}

	var ports stack.PortOrIdentRange
	if changePort {
		ports = stack.PortOrIdentRange{
			Start: uint16(minProto),
			Size:  maxProto - minProto + 1,
		}
	}

	// Redirect is destination NAT to the local address.
	if !pkt.ConfigureNAT(ports, addr, stack.DNAT, changePort, true /* changeAddress */) {
		regs.verdict.Code = VC(linux.NF_DROP)
		return
	}
	regs.verdict.Code = VC(linux.NF_ACCEPT)
}

// GetExprName implements operation.GetExprName.
func (rd *redirOp) GetExprName() string {
	return OpTypeRedir.String()
}

// deepCopy implements operation.deepCopy.
func (rd *redirOp) deepCopy() operation {
	opCopy := *rd
	return &opCopy
}

// Dump implements operation.Dump.
func (rd *redirOp) Dump() ([]byte, *syserr.AnnotatedError) {
	msg := &nlmsg.Message{}
	if rd.flags != 0 {
		msg.PutAttr(linux.NFTA_REDIR_FLAGS, nlmsg.PutU32(nlmsg.HostToNetU32(rd.flags)))
	}
	if rd.sregProtoMinIdx >= 0 {
		msg.PutAttr(linux.NFTA_REDIR_REG_PROTO_MIN, formatRegIdxForDump(int(rd.sregProtoMinIdx)))
		msg.PutAttr(linux.NFTA_REDIR_REG_PROTO_MAX, formatRegIdxForDump(int(rd.sregProtoMaxIdx)))
	}
	return msg.Buffer(), nil
}

// checkCompatibility ensures the redirect operation is used in a valid chain.
// Ref: net/netfilter/nft_redir.c:nft_redir_validate()
func (rd *redirOp) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	chain := cCtx.chain
	if !chain.IsBaseChain() {
		return nil
	}
	hook := chain.baseChainInfo.Hook
	if hook != stack.NFPrerouting && hook != stack.NFOutput {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "redir expression is only valid in prerouting and output hooks")
	}
	if chain.baseChainInfo.BcType != BaseChainTypeNat {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "redir expression is only valid in NAT chains")
	}
	return nil
}

// Ref: net/netfilter/nft_redir.c:nft_redir_policy
var redirAttrPolicy = []NlaPolicy{
	linux.NFTA_REDIR_REG_PROTO_MIN: {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_REDIR_REG_PROTO_MAX: {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_REDIR_FLAGS:         {nlaType: linux.NLA_BE32, validator: AttrMaskValidator[uint32](linux.NF_NAT_RANGE_MASK)},
}

// initRedirOp initializes a redirect operation from the given expression info.
// Ref: net/netfilter/nft_redir.c:nft_redir_init()
func initRedirOp(tab *Table, exprInfo ExprInfo) (*redirOp, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: redirAttrPolicy,
	})
	if err != nil {
		return nil, err
	}

	// Use flag value as 0 if not set; the error can be ignored here.
	flags, _ := AttrNetToHost[uint32](linux.NFTA_REDIR_FLAGS, attrs)
	regProtoMin, regProtoMinOk := AttrNetToHost[uint32](linux.NFTA_REDIR_REG_PROTO_MIN, attrs)

	sregProtoMin, sregProtoMax := -1, -1
	if regProtoMinOk {
		sregProtoMin = int(regProtoMin)
		regProtoMax, regProtoMaxOk := AttrNetToHost[uint32](linux.NFTA_REDIR_REG_PROTO_MAX, attrs)
		if !regProtoMaxOk {
			sregProtoMax = sregProtoMin
		} else {
			sregProtoMax = int(regProtoMax)
		}
	}

	return newRedirOp(sregProtoMin, sregProtoMax, flags)
}
