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

// This file implements the "MASQUERADE" XTables compatibility target operation.
// Ref: net/netfilter/xt_masquerade.c

package nftables

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// masqTargetInfo stores precomputed port range parameters for masq target.
// Ref: net/netfilter/xt_masquerade.c
type masqTargetInfo struct {
	// netProto is the expected network protocol number (IPv4 or IPv6).
	netProto tcpip.NetworkProtocolNumber
	// hasPortRange indicates if a custom port range was specified.
	hasPortRange bool
	// portsOrIdents specifies the port range to map.
	portsOrIdents stack.PortOrIdentRange
}

// compatMASQTarget implements the xtables MASQUERADE target extension.
type compatMASQTarget struct {
	// revision is the XTables MASQUERADE target extension revision.
	revision uint32
	// infoData is the raw netlink attribute payload; saved for dump.
	infoData []byte
	// info contains the port range parameters.
	info masqTargetInfo
}

// evaluate implements operation.evaluate.
// Ref: net/netfilter/xt_masquerade.c:masquerade_tg()
func (op *compatMASQTarget) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	opInfo := &op.info
	if evalCtx.pkt.NetworkProtocolNumber != opInfo.netProto {
		return
	}
	pkt := evalCtx.pkt
	portsOrIdents := stack.PortOrIdentRange{Start: 0, Size: 1}
	// Determine the port range to masquerade.
	if opInfo.hasPortRange {
		portsOrIdents = opInfo.portsOrIdents
	} else {
		switch pkt.TransportProtocolNumber {
		case header.UDPProtocolNumber:
			if len(pkt.TransportHeader().Slice()) >= header.UDPMinimumSize {
				portsOrIdents = targetPortRangeForTCPAndUDP(header.UDP(pkt.TransportHeader().Slice()).SourcePort())
			}
		case header.TCPProtocolNumber:
			if len(pkt.TransportHeader().Slice()) >= header.TCPMinimumSize {
				portsOrIdents = targetPortRangeForTCPAndUDP(header.TCP(pkt.TransportHeader().Slice()).SourcePort())
			}
		case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
			portsOrIdents = stack.PortOrIdentRange{Start: 0, Size: math.MaxUint16 + 1}
		default:
			portsOrIdents = stack.PortOrIdentRange{Start: 0, Size: 1}
		}
	}

	// Configure NAT Masq.
	if !pkt.ConfigureMasquerade(portsOrIdents, evalCtx.route, evalCtx.nftState.stack, true /* changePort */) {
		regs.verdict.Code = VC(linux.NF_DROP)
		return
	}
	regs.verdict = Verdict{Code: VC(linux.NF_ACCEPT)}
}

// checkCompatibility implements operation.checkCompatibility.
// Ref: net/netfilter/x_tables.c:xt_check_target
func (op *compatMASQTarget) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	chain := cCtx.chain
	if !chain.IsBaseChain() {
		return nil
	}
	if chain.baseChainInfo.Hook != stack.NFPostrouting {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade target expression is only valid in postrouting hook")
	}
	if chain.baseChainInfo.BcType != BaseChainTypeNat {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade target expression is only valid in NAT chains")
	}
	return nil
}

// deepCopy implements operation.deepCopy.
func (op *compatMASQTarget) deepCopy() operation {
	opCopy := *op
	opCopy.infoData = append([]byte(nil), op.infoData...)
	return &opCopy
}

// updateReferences implements operation.updateReferences.
func (op *compatMASQTarget) updateReferences(table *Table, sourceTable *Table, sourceOp operation) {}

// destroy implements operation.destroy.
func (op *compatMASQTarget) destroy() {}

// GetExprName implements operation.GetExprName.
func (op *compatMASQTarget) GetExprName() string {
	return OpTypeTarget.String()
}

// Dump implements operation.Dump.
// Ref: net/netfilter/nft_compat.c:nft_target_dump()
func (op *compatMASQTarget) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttrString(linux.NFTA_TARGET_NAME, TargetMASQUERADE)
	m.PutAttr(linux.NFTA_TARGET_REV, nlmsg.PutU32(op.revision))
	if len(op.infoData) > 0 {
		m.PutAttr(linux.NFTA_TARGET_INFO, primitive.AsByteSlice(op.infoData))
	}
	return m.Buffer(), nil
}

func (info *masqTargetInfo) init(netProto tcpip.NetworkProtocolNumber, flags uint32, minProto, maxProto uint16) *syserr.AnnotatedError {
	if flags&linux.NF_NAT_RANGE_MAP_IPS != 0 {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade does not support MAP_IPS")
	}

	info.netProto = netProto
	info.portsOrIdents = stack.PortOrIdentRange{Start: 0, Size: 1}
	if flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED != 0 {
		minPort := nlmsg.NetToHostU16(minProto)
		maxPort := nlmsg.NetToHostU16(maxProto)
		if minPort > maxPort {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid port range: min (%d) > max (%d)", minPort, maxPort))
		}
		info.hasPortRange = true
		info.portsOrIdents = stack.PortOrIdentRange{
			Start: minPort,
			Size:  uint32(maxPort) - uint32(minPort) + 1,
		}
	}
	return nil
}

// unmarshalIPv4 parses nf_nat_ipv4_multi_range_compat and fills masqTargetInfo.
func (info *masqTargetInfo) unmarshalIPv4(infoData []byte) *syserr.AnnotatedError {
	var mr linux.NfNATIPV4MultiRangeCompat
	if len(infoData) < mr.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade info too small for IPv4")
	}
	mr.UnmarshalBytes(infoData[:mr.SizeBytes()])

	if mr.RangeSize != 1 {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade requires rangesize to be 1")
	}
	return info.init(header.IPv4ProtocolNumber, mr.RangeIPV4.Flags, mr.RangeIPV4.MinPort, mr.RangeIPV4.MaxPort)
}

// unmarshalIPv6 parses nf_nat_range and fills masqTargetInfo.
func (info *masqTargetInfo) unmarshalIPv6(infoData []byte) *syserr.AnnotatedError {
	var r linux.NFNATRange
	if len(infoData) < r.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade info too small for IPv6")
	}
	r.UnmarshalBytes(infoData[:r.SizeBytes()])
	return info.init(header.IPv6ProtocolNumber, r.Flags, r.MinProto, r.MaxProto)
}

const (
	masqSupportedRevision = 0
)

// lookupMasqRevision validates if a masquerade target revision is supported
// and returns the best revision.
func lookupMasqRevision(rev uint32, family stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	if family != stack.IP && family != stack.IP6 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("masquerade target not supported for family %v", family))
	}
	if rev != masqSupportedRevision {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("masquerade revision %d not supported", rev))
	}
	return masqSupportedRevision, nil
}

// parseMasqTarget converts MASQUERADE target data into info data.
// Ref: net/netfilter/xt_masquerade.c:masquerade_tg_check()
func parseMasqTarget(tab *Table, rev uint32, infoData []byte) (*masqTargetInfo, *syserr.AnnotatedError) {
	if tab.name != TableNameNAT {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "masquerade only valid in nat table")
	}
	if rev != masqSupportedRevision {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("masquerade revision %d not supported", rev))
	}
	info := &masqTargetInfo{}
	var err *syserr.AnnotatedError
	switch tab.GetAddressFamily() {
	case stack.IP:
		err = info.unmarshalIPv4(infoData)
	case stack.IP6:
		err = info.unmarshalIPv6(infoData)
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("masquerade target unsupported address family: %v", tab.GetAddressFamily()))
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}
