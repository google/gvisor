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

// nat corresponds to the NFT_NAT expression.
type natOp struct {
	sregAddrMinIdx  int8          // Index of the source register for the minimum address in the register set.
	sregAddrMaxIdx  int8          // Index of the source register for the maximum address in the register set.
	sregProtoMinIdx int8          // Index of the source register for the minimum protocol in the register setl.
	sregProtoMaxIdx int8          // Index of the source register for the maximum protocol in the register set.
	manipType       stack.NATType // Type of NAT operation, either SNAT or DNAT.
	family          uint8         // Address family of the NAT operation, either IPv4 or IPv6.
	flags           uint16        // Flags for the NAT operation.
}

// regIdxOrDefault returns the register index if it is valid
// otherwise returns the default value.
func regIdxOrDefault(reg int8, len int, defaultIdx int8) int8 {
	if reg < 0 {
		return defaultIdx
	}
	v, err := regNumToIdx(uint8(reg), len)
	if err == nil {
		return int8(v)
	}
	return defaultIdx
}

// newNATOp creates a new NAT operation.
func newNATOp(nt, family uint8, sregAddrMin, sregAddrMax, sregProtoMin, sregProtoMax int8, flags uint16) (*natOp, *syserr.AnnotatedError) {
	natOp := &natOp{
		family: family,
		flags:  flags,
	}
	natOp.manipType = stack.ToNATType(nt)
	if natOp.manipType == stack.NATUnknown {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Invalid NAT type")
	}
	switch family {
	case linux.NFPROTO_IPV4:
		natOp.sregAddrMinIdx = regIdxOrDefault(sregAddrMin, 4, -1)
		natOp.sregAddrMaxIdx = regIdxOrDefault(sregAddrMax, 4, natOp.sregAddrMinIdx)
	case linux.NFPROTO_IPV6:
		natOp.sregAddrMinIdx = regIdxOrDefault(sregAddrMin, 16, -1)
		natOp.sregAddrMaxIdx = regIdxOrDefault(sregAddrMax, 16, natOp.sregAddrMinIdx)
	}
	natOp.sregProtoMinIdx = regIdxOrDefault(sregProtoMin, 2, -1)
	natOp.sregProtoMaxIdx = regIdxOrDefault(sregProtoMax, 2, natOp.sregProtoMinIdx)
	return natOp, nil
}

// nfNatRange is the equivalent of struct nf_nat_range2 in Linux.
type nfNatRange struct {
	minAddr  tcpip.Address
	maxAddr  tcpip.Address
	minProto uint16
	maxProto uint16
	flags    uint16
}

// setupAddr returns the min and max addresses from the register set.
func (n *natOp) getAddrRange(regs *registerSet) (minAddr, maxAddr tcpip.Address) {
	regBuffer := regs.data
	switch n.family {
	case linux.NFPROTO_IPV4:
		minAddr = tcpip.AddrFromSlice(regBuffer[n.sregAddrMinIdx : n.sregAddrMinIdx+4])
		maxAddr = tcpip.AddrFromSlice(regBuffer[n.sregAddrMaxIdx : n.sregAddrMaxIdx+4])
	case linux.NFPROTO_IPV6:
		minAddr = tcpip.AddrFromSlice(regBuffer[n.sregAddrMinIdx : n.sregAddrMinIdx+16])
		maxAddr = tcpip.AddrFromSlice(regBuffer[n.sregAddrMaxIdx : n.sregAddrMaxIdx+16])
	}
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
func (n *natOp) setupNetmap(pkt *stack.PacketBuffer, minAddr, maxAddr *tcpip.Address) {
	var manipAddr tcpip.Address
	var addrLen int

	switch n.manipType {
	case stack.SNAT:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			manipAddr = pkt.Network().SourceAddress()
			addrLen = header.IPv4AddressSize
		} else {
			manipAddr = pkt.Network().SourceAddress()
			addrLen = header.IPv6AddressSize
		}
	case stack.DNAT:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			manipAddr = pkt.Network().DestinationAddress()
			addrLen = header.IPv4AddressSize
		} else {
			manipAddr = pkt.Network().DestinationAddress()
			addrLen = header.IPv6AddressSize
		}
	}

	manipAddrSlice := manipAddr.AsSlice()
	minSlice := minAddr.AsSlice()
	maxSlice := maxAddr.AsSlice()
	newAddrBytes := make([]byte, addrLen)
	words := addrLen / 4
	for i := 0; i < words; i++ {
		offset := i * 4
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
func (n *natOp) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
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

	// TODO: b/486197011 - Implement NAT operation.
	log.Warningf("Nftables: natOp.evaluate() is not implemented, changeAddress=%t, changePort=%t, minAddr=%s, maxAddr=%s, minProto=%d, maxProto=%d", changeAddress, changePort, minAddr, maxAddr, minProto, maxProto)
}

func (n *natOp) GetExprName() string {
	return OpTypeNAT.String()
}

func (n *natOp) Dump() ([]byte, *syserr.AnnotatedError) {
	log.Warningf("Nftables: natOp.Dump() is not implemented")
	return nil, nil
}

var natAttrPolicy = []NlaPolicy{
	linux.NFTA_NAT_TYPE:          {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_FAMILY:        {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_REG_ADDR_MIN:  {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_REG_ADDR_MAX:  {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_REG_PROTO_MIN: {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_REG_PROTO_MAX: {nlaType: linux.NLA_U32},
	linux.NFTA_NAT_FLAGS:         {nlaType: linux.NLA_BE32, validator: AttrMaskValidator[uint32](linux.NF_NAT_RANGE_MASK)},
}

// initNATOp initializes a NAT operation from the given expression information.
// Similar to `nft_nat_init` in kernel.
func initNATOp(tab *Table, exprInfo ExprInfo) (*natOp, *syserr.AnnotatedError) {
	attrs, ok := NfParseWithPolicy(exprInfo.ExprData, natAttrPolicy)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse NAT expression data")
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
	sregAddrMin, sregAddrMax := int8(-1), int8(-1)
	if regAddrMinOk {
		sregAddrMin = int8(regAddrMin)
		regAddrMax, regAddrMaxOk := AttrNetToHost[uint32](linux.NFTA_NAT_REG_ADDR_MAX, attrs)
		if !regAddrMaxOk {
			sregAddrMax = sregAddrMin
		} else {
			sregAddrMax = int8(regAddrMax)
		}
		flags |= linux.NF_NAT_RANGE_MAP_IPS
	}

	sregProtoMin, sregProtoMax := int8(-1), int8(-1)
	if regProtoMinOk {
		sregProtoMin = int8(regProtoMin)
		regProtoMax, regProtoMaxOk := AttrNetToHost[uint32](linux.NFTA_NAT_REG_PROTO_MAX, attrs)
		if !regProtoMaxOk {
			sregProtoMax = sregProtoMin
		} else {
			sregProtoMax = int8(regProtoMax)
		}
		flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}

	return newNATOp(uint8(nt), uint8(family), sregAddrMin, sregAddrMax, sregProtoMin, sregProtoMax, uint16(flags))
}
