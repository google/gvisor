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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserr"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// natOp represents the NFT_NAT expression.
type natOp struct {
	// sregAddrMinIdx is the starting index in the register set to read/write address min data.
	sregAddrMinIdx int8
	// sregAddrMaxIdx is the starting index in the register set to read/write address max data.
	sregAddrMaxIdx int8
	// sregProtoMinIdx is the starting index in the register set to read/write proto min data.
	sregProtoMinIdx int8
	// sregProtoMaxIdx is the starting index in the register set to read/write proto max data.
	sregProtoMaxIdx int8
	// manipType is the type of NAT operation, either SNAT or DNAT.
	manipType stack.NATType
	// family is the Address family of the NAT operation, either IPv4 or IPv6.
	family uint8
	// flags is the flags for the NAT operation.
	flags uint16
}

// newNATOp creates a new NAT operation.
func newNATOp(nt, family uint8, sregAddrMin, sregAddrMax, sregProtoMin, sregProtoMax int, flags uint16) (*natOp, *syserr.AnnotatedError) {
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

	natOp := &natOp{
		family: family,
		flags:  flags,
	}
	natOp.manipType = stack.ToNATType(nt)
	if natOp.manipType == stack.NATUnknown {
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Invalid NAT type")
	}
	len := header.IPv4AddressSize
	if family == linux.NFPROTO_IPV6 {
		len = header.IPv6AddressSize
	}

	var err *syserr.AnnotatedError
	if natOp.sregAddrMinIdx, err = regIdxOrDefault(sregAddrMin, len, unsetReg); err != nil {
		return nil, err
	}

	// addr max is set to min if not set.
	if natOp.sregAddrMaxIdx, err = regIdxOrDefault(sregAddrMax, len, natOp.sregAddrMinIdx); err != nil {
		return nil, err
	}

	protoLen := linux.SizeOfNfConntrackManProto
	if natOp.sregProtoMinIdx, err = regIdxOrDefault(sregProtoMin, protoLen, unsetReg); err != nil {
		return nil, err
	}

	// proto max is set to proto min if not set.
	if natOp.sregProtoMaxIdx, err = regIdxOrDefault(sregProtoMax, protoLen, natOp.sregProtoMinIdx); err != nil {
		return nil, err
	}

	return natOp, nil
}

func (n *natOp) deepCopy() operation {
	opCopy := *n
	return &opCopy
}

// nfNatRange is the equivalent of struct nf_nat_range2 in Linux.
type nfNatRange struct {
	minAddr  tcpip.Address
	maxAddr  tcpip.Address
	minProto uint16
	maxProto uint16
	flags    uint16
}

// getAddrRange returns the min and max addresses from the register set.
func (n *natOp) getAddrRange(regs *registerSet) (minAddr, maxAddr tcpip.Address) {
	regBuffer := regs.data
	sz := header.IPv4AddressSize
	if n.family == linux.NFPROTO_IPV6 {
		sz = header.IPv6AddressSize
	}
	minAddr = tcpip.AddrFromSlice(regBuffer[n.sregAddrMinIdx : int(n.sregAddrMinIdx)+sz])
	maxAddr = tcpip.AddrFromSlice(regBuffer[n.sregAddrMaxIdx : int(n.sregAddrMaxIdx)+sz])
	return
}

// getProtoRange returns the min max proto data.
// For example, for tcp/udp this proto data is the port range.
// See `nf_conntrack_man_proto` in kernel.
func (n *natOp) getProtoRange(regs *registerSet) (minProto, maxProto uint32) {
	regBuffer := regs.data
	minBuf := regBuffer[n.sregProtoMinIdx : n.sregProtoMinIdx+2]
	minProto = uint32(minBuf[0])<<8 | uint32(minBuf[1])
	maxBuf := regBuffer[n.sregProtoMaxIdx : n.sregProtoMaxIdx+2]
	maxProto = uint32(maxBuf[0])<<8 | uint32(maxBuf[1])
	return
}

// setupNetmap sets up the netmap for the NAT operation.
// See `nft_nat_setup_netmap` in kernel.
// TODO: b/486197011 - Support and verify netmaps.
func (n *natOp) setupNetmap(pkt *stack.PacketBuffer, minAddr, maxAddr *tcpip.Address) {
	var manipAddr tcpip.Address
	var addrLen int

	switch n.manipType {
	case stack.SNAT:
		manipAddr = pkt.Network().SourceAddress()
	case stack.DNAT:
		manipAddr = pkt.Network().DestinationAddress()
	}

	addrLen = header.IPv4AddressSize
	if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		addrLen = header.IPv6AddressSize
	}

	manipAddrSlice := manipAddr.AsSlice()
	minSlice := minAddr.AsSlice()
	maxSlice := maxAddr.AsSlice()
	newAddrBytes := make([]byte, addrLen)
	words := addrLen / 4 // size of uint32
	for i := 0; i < words; i++ {
		offset := i * 4 // offset in bytes
		m := binary.BigEndian.Uint32(manipAddrSlice[offset:])
		min := binary.BigEndian.Uint32(minSlice[offset:])
		max := binary.BigEndian.Uint32(maxSlice[offset:])

		netmask := ^(min ^ max)
		m &= ^netmask
		m |= min & netmask
		binary.BigEndian.PutUint32(newAddrBytes[offset:], m)
	}

	*minAddr = tcpip.AddrFromSlice(newAddrBytes)
	*maxAddr = *minAddr
}

// evaluate performs NAT setup on the connection.
// Called when the packet matches the NAT op configured.
func (n *natOp) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	pkt := evalCtx.pkt
	// Skip the rule if the packet's family does not match the configured rule
	// family. With an `inet` table the same base chain is dispatched for both
	// IPv4 and IPv6 packets, so this mismatch is reachable in practice and
	// must not panic inside setupNetmap. Matches the behavior of nft_nat_eval
	// in linux/net/netfilter/nft_nat.c.
	switch n.family {
	case linux.NFPROTO_IPV4:
		if pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber {
			return
		}
	case linux.NFPROTO_IPV6:
		if pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
			return
		}
	}

	// Just fill the data for the NAT operation.
	changeAddress := false
	changePort := false
	var minAddr, maxAddr tcpip.Address
	if n.sregAddrMinIdx >= 0 {
		changeAddress = true
		minAddr, maxAddr = n.getAddrRange(regs)
		if (n.flags & linux.NF_NAT_RANGE_MAP_IPS) != 0 {
			n.setupNetmap(pkt, &minAddr, &maxAddr)
		}
	}

	var minProto, maxProto uint32
	if n.sregProtoMinIdx >= 0 {
		changePort = true
		minProto, maxProto = n.getProtoRange(regs)
	}

	ports := stack.PortOrIdentRange{
		Start: uint16(minProto),
		Size:  maxProto - minProto + 1,
	}

	// Configure NAT for the packet.
	if !pkt.ConfigureNAT(ports, minAddr, n.manipType, changePort, changeAddress) {
		regs.verdict.Code = VC(linux.NF_DROP)
		return
	}
	// NAT successful, set verdict to ACCEPT.
	regs.verdict.Code = VC(linux.NF_ACCEPT)
}

// GetExprName returns the name of the expression.
func (n *natOp) GetExprName() string {
	return OpTypeNAT.String()
}

// Dump dumps the operation info.
func (n *natOp) Dump() ([]byte, *syserr.AnnotatedError) {
	log.Warningf("Nftables: natOp.Dump() is not implemented")
	return nil, nil
}

// checkCompatibility implements operation.checkCompatibility.
func (n *natOp) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

var natAttrPolicy = []NlaPolicy{
	linux.NFTA_NAT_TYPE:          {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_FAMILY:        {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_REG_ADDR_MIN:  {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_NAT_REG_ADDR_MAX:  {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_NAT_REG_PROTO_MIN: {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_NAT_REG_PROTO_MAX: {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_NAT_FLAGS:         {nlaType: linux.NLA_BE32, validator: AttrMaskValidator[uint32](linux.NF_NAT_RANGE_MASK)},
}

// initNATOp initializes a NAT operation from the given expression information.
// Similar to `nft_nat_init` in kernel.
func initNATOp(tab *Table, exprInfo ExprInfo) (*natOp, *syserr.AnnotatedError) {
	attrs, parseErr := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: natAttrPolicy,
	})
	if parseErr != nil {
		return nil, parseErr
	}

	nt, typeOk := AttrNetToHost[uint32](linux.NFTA_NAT_TYPE, attrs)
	regAddrMin, regAddrMinOk := AttrNetToHost[uint32](linux.NFTA_NAT_REG_ADDR_MIN, attrs)
	regProtoMin, regProtoMinOk := AttrNetToHost[uint32](linux.NFTA_NAT_REG_PROTO_MIN, attrs)

	if !typeOk || !(regAddrMinOk || regProtoMinOk) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse NAT expression data")
	}

	family, familyOk := AttrNetToHost[uint32](linux.NFTA_NAT_FAMILY, attrs)
	if !familyOk {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse NAT family expression data")
	}
	af, err := AFtoNetlinkAF(uint8(family))
	if err != nil {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to convert family to AF")
	}
	tf := tab.GetAddressFamily()
	if tf != stack.Inet && tf != af {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse NAT family expression data")
	}

	flags, _ := AttrNetToHost[uint32](linux.NFTA_NAT_FLAGS, attrs)
	sregAddrMin, sregAddrMax := -1, -1
	if regAddrMinOk {
		sregAddrMin = int(regAddrMin)
		regAddrMax, regAddrMaxOk := AttrNetToHost[uint32](linux.NFTA_NAT_REG_ADDR_MAX, attrs)
		if !regAddrMaxOk {
			sregAddrMax = sregAddrMin
		} else {
			sregAddrMax = int(regAddrMax)
		}
		flags |= linux.NF_NAT_RANGE_MAP_IPS
	}

	sregProtoMin, sregProtoMax := -1, -1
	if regProtoMinOk {
		sregProtoMin = int(regProtoMin)
		regProtoMax, regProtoMaxOk := AttrNetToHost[uint32](linux.NFTA_NAT_REG_PROTO_MAX, attrs)
		if !regProtoMaxOk {
			sregProtoMax = sregProtoMin
		} else {
			sregProtoMax = int(regProtoMax)
		}
		flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}

	return newNATOp(uint8(nt), uint8(family), sregAddrMin, sregAddrMax, sregProtoMin, sregProtoMax, uint16(flags))
}
