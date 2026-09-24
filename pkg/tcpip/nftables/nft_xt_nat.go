// Copyright 2026 The gVisor Authors.
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

// This file implements the NAT XTables compatibility target operations.
// Ref: net/netfilter/xt_nat.c

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// natTargetInfo stores params for SNAT/DNAT target.
// Ref: net/netfilter/nft_nat.c
type natTargetInfo struct {
	// netProto is the expected network protocol number (IPv4 or IPv6).
	netProto tcpip.NetworkProtocolNumber
	// natType indicates SNAT or DNAT.
	natType stack.NATType
	// address is the NAT address.
	address tcpip.Address
	// portsOrIdents specifies the port range to map.
	portsOrIdents stack.PortOrIdentRange
	// changePort represents if port should be changed.
	changePort bool
	// changeAddress represents if address should be changed.
	changeAddress bool
}

// compatNATTarget implements the xtables SNAT and DNAT target extensions.
type compatNATTarget struct {
	// name is the name of the NAT target extension ("SNAT" or "DNAT").
	name string
	// revision is the XTables NAT target extension revision (0, 1, ...).
	revision uint32
	// infoData is the raw netlink attribute payload; saved for dump.
	infoData []byte
	// info holds the NAT params.
	info natTargetInfo
}

// evaluate implements operation.evaluate.
// Ref: net/netfilter/nft_nat.c:nft_nat_eval()
func (op *compatNATTarget) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	opInfo := &op.info
	if evalCtx.pkt.NetworkProtocolNumber != opInfo.netProto {
		return
	}
	if !evalCtx.pkt.ConfigureNAT(opInfo.portsOrIdents, opInfo.address, opInfo.natType, opInfo.changePort, opInfo.changeAddress) {
		regs.verdict.Code = VC(linux.NF_DROP)
		return
	}
	regs.verdict = Verdict{Code: VC(linux.NF_ACCEPT)}
}

// checkCompatibility implements operation.checkCompatibility.
// Ref: net/netfilter/x_tables.c:xt_check_target
func (op *compatNATTarget) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	chain := cCtx.chain
	if !chain.IsBaseChain() {
		return nil
	}
	opInfo := &op.info
	switch opInfo.natType {
	case stack.SNAT:
		if chain.baseChainInfo.Hook != stack.NFPostrouting && chain.baseChainInfo.Hook != stack.NFInput {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "SNAT target expression only valid in postrouting or input hook")
		}
	case stack.DNAT:
		if chain.baseChainInfo.Hook != stack.NFPrerouting && chain.baseChainInfo.Hook != stack.NFOutput {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "DNAT target expression only valid in prerouting or output hook")
		}
	}
	if chain.baseChainInfo.BcType != BaseChainTypeNat {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NAT target expression only valid in NAT chains")
	}
	return nil
}

// deepCopy implements operation.deepCopy.
func (op *compatNATTarget) deepCopy() operation {
	opCopy := *op
	opCopy.infoData = append([]byte(nil), op.infoData...)
	return &opCopy
}

// updateReferences implements operation.updateReferences.
func (op *compatNATTarget) updateReferences(table *Table, sourceTable *Table, sourceOp operation) {}

// destroy implements operation.destroy.
func (op *compatNATTarget) destroy() {}

// GetExprName implements operation.GetExprName.
func (op *compatNATTarget) GetExprName() string {
	return OpTypeTarget.String()
}

// Dump implements operation.Dump.
// Ref: net/netfilter/nft_compat.c:nft_target_dump()
func (op *compatNATTarget) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttrString(linux.NFTA_TARGET_NAME, op.name)
	m.PutAttr(linux.NFTA_TARGET_REV, nlmsg.PutU32(op.revision))
	if len(op.infoData) > 0 {
		m.PutAttr(linux.NFTA_TARGET_INFO, primitive.AsByteSlice(op.infoData))
	}
	return m.Buffer(), nil
}

func (info *natTargetInfo) init(name string, tab *Table, flags uint32, minAddrSlice []byte, minProto, maxProto uint16) *syserr.AnnotatedError {
	var netProto tcpip.NetworkProtocolNumber
	switch tab.GetAddressFamily() {
	case stack.IP:
		netProto = header.IPv4ProtocolNumber
	case stack.IP6:
		netProto = header.IPv6ProtocolNumber
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("NAT target unsupported address family: %v", tab.GetAddressFamily()))
	}

	natType := stack.SNAT
	if name == TargetDNAT {
		natType = stack.DNAT
	}

	info.netProto = netProto
	info.natType = natType
	info.address = tcpip.AddrFromSlice(minAddrSlice)
	info.changeAddress = (flags & linux.NF_NAT_RANGE_MAP_IPS) != 0
	info.changePort = (flags & linux.NF_NAT_RANGE_PROTO_SPECIFIED) != 0
	info.portsOrIdents = stack.PortOrIdentRange{Start: 0, Size: 1}
	if info.changePort {
		minPort := nlmsg.NetToHostU16(minProto)
		maxPort := nlmsg.NetToHostU16(maxProto)
		if minPort > maxPort {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid port range: min (%d) > max (%d)", minPort, maxPort))
		}
		info.portsOrIdents = stack.PortOrIdentRange{
			Start: minPort,
			Size:  uint32(maxPort) - uint32(minPort) + 1,
		}
	}
	return nil
}

// unmarshalRev0 parses nf_nat_ipv4_multi_range_compat and fills natTargetInfo.
func (info *natTargetInfo) unmarshalRev0(name string, tab *Table, infoData []byte) *syserr.AnnotatedError {
	if tab.GetAddressFamily() != stack.IP {
		return syserr.NewAnnotatedError(syserr.ErrNoSuchFile, "NAT revision 0 is only valid for IPv4")
	}
	var mr linux.NfNATIPV4MultiRangeCompat
	if len(infoData) < mr.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NAT info too small for revision 0")
	}
	mr.UnmarshalBytes(infoData[:mr.SizeBytes()])
	if mr.RangeSize != 1 {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NAT requires rangesize to be 1")
	}
	return info.init(name, tab, mr.RangeIPV4.Flags, mr.RangeIPV4.MinIP[:4], mr.RangeIPV4.MinPort, mr.RangeIPV4.MaxPort)
}

// unmarshalRev1 parses nf_nat_range and fills natTargetInfo.
func (info *natTargetInfo) unmarshalRev1(name string, tab *Table, infoData []byte) *syserr.AnnotatedError {
	var r1 linux.NFNATRange
	if len(infoData) < r1.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NAT info too small for revision 1")
	}
	r1.UnmarshalBytes(infoData[:r1.SizeBytes()])
	var minAddrSlice []byte
	if tab.GetAddressFamily() == stack.IP {
		minAddrSlice = r1.MinAddr[:4]
	} else {
		minAddrSlice = r1.MinAddr[:]
	}
	return info.init(name, tab, r1.Flags, minAddrSlice, r1.MinProto, r1.MaxProto)
}

// unmarshalRev2 parses nf_nat_range2 and fills natTargetInfo.
func (info *natTargetInfo) unmarshalRev2(name string, tab *Table, infoData []byte) *syserr.AnnotatedError {
	var r2 linux.NFNATRange2
	if len(infoData) < r2.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NAT info too small for revision 2")
	}
	r2.UnmarshalBytes(infoData[:r2.SizeBytes()])
	var minAddrSlice []byte
	if tab.GetAddressFamily() == stack.IP {
		minAddrSlice = r2.MinAddr[:4]
	} else {
		minAddrSlice = r2.MinAddr[:]
	}
	return info.init(name, tab, r2.Flags, minAddrSlice, r2.MinProto, r2.MaxProto)
}

const (
	natRevision0   = 0
	natRevision1   = 1
	natRevision2   = 2
	natMaxRevision = natRevision2
)

// lookupNATRevision validates if a NAT target revision is supported
// and returns the best revision.
func lookupNATRevision(name string, rev uint32, family stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	if rev == natRevision0 && family != stack.IP {
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("%s revision 0 only supported for IPv4", name))
	}
	if rev > natMaxRevision {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("%s revision %d not supported", name, rev))
	}
	return natMaxRevision, nil
}

// parseNATTarget converts SNAT/DNAT target data into info data.
// Ref: net/netfilter/xt_nat.c:xt_nat_target_reg
func parseNATTarget(name string, tab *Table, rev uint32, infoData []byte) (*natTargetInfo, *syserr.AnnotatedError) {
	if tab.name != TableNameNAT {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("%s target only valid in nat table, not %s", name, tab.name))
	}
	info := &natTargetInfo{}
	var err *syserr.AnnotatedError
	switch rev {
	case natRevision0:
		err = info.unmarshalRev0(name, tab, infoData)
	case natRevision1:
		err = info.unmarshalRev1(name, tab, infoData)
	case natRevision2:
		err = info.unmarshalRev2(name, tab, infoData)
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("NAT revision %d not supported", rev))
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}
