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

// This file implements the "addrtype" XTables compatibility match operation.
// Ref: net/netfilter/xt_addrtype.c

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// addrTypeMatchInfo stores params for addrtype match evaluation.
// Ref: net/netfilter/xt_addrtype.c:xt_addrtype_info_v1
type addrTypeMatchInfo struct {
	// sourceMask is the bitmask of XT_ADDRTYPE_* types allowed for the source address.
	sourceMask uint16
	// destMask is the bitmask of XT_ADDRTYPE_* types allowed for the destination address.
	destMask uint16
	// checkSrc represents if source address type checking is enabled.
	checkSrc bool
	// invertSrcMatch represents if the source address type match result should be inverted.
	invertSrcMatch bool
	// limitIfaceIn represents if the address type checks should be
	// constrained to the input interface.
	limitIfaceIn bool
	// checkDst represents if the destination address type checking is enabled.
	checkDst bool
	// invertDstMatch represents whether the destination address type match result should be inverted.
	invertDstMatch bool
	// limitIfaceOut represents whether address type checks should be
	// constrained to the outgoing interface.
	limitIfaceOut bool
}

// compatAddrtypeMatch implements the "addrtype" xtables match extension.
// It evaluates source and destination routing address types against FIB route lookups.
type compatAddrtypeMatch struct {
	// revision is the XTables addrtype match extension revision (0 or 1).
	revision uint32
	// infoData is the raw netlink attribute payload for serialization (NFTA_MATCH_INFO).
	infoData []byte
	// info holds the precomputed source/destination masks and interface limit flags.
	info addrTypeMatchInfo
}

// match returns true if the packet matches the address type.
// Ref: net/netfilter/xt_addrtype.c:addrtype_mt_v1()
func (op *compatAddrtypeMatch) match(evalCtx opEvalCtx) bool {
	pkt := evalCtx.pkt
	if !fibValidatePktHeader(pkt) {
		return false
	}
	srcAddr, dstAddr, ok := fibGetSrcDstAddr(pkt)
	if !ok {
		return false
	}

	route := evalCtx.route
	stk := evalCtx.nftState.stack
	netProto := pkt.NetworkProtocolNumber
	opInfo := &op.info

	nicID := tcpip.NICID(0)
	if opInfo.limitIfaceIn {
		nicID = pkt.InputNICID
	} else if opInfo.limitIfaceOut && route != nil {
		nicID = route.OutgoingNIC()
	}

	if opInfo.checkSrc {
		addrType := fibGetAddrRouteType(netProto, stk, srcAddr, nicID, route)
		xtAddrType := routeAddrTypeToXTAddrType(addrType)
		matched := ((xtAddrType & opInfo.sourceMask) != 0) != opInfo.invertSrcMatch
		if !matched {
			return false
		}
	}

	if opInfo.checkDst {
		addrType := fibGetAddrRouteType(netProto, stk, dstAddr, nicID, route)
		xtAddrType := routeAddrTypeToXTAddrType(addrType)
		matched := ((xtAddrType & opInfo.destMask) != 0) != opInfo.invertDstMatch
		if !matched {
			return false
		}
	}

	return true
}

// evaluate implements operation.evaluate.
func (op *compatAddrtypeMatch) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	if !op.match(evalCtx) {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}
	regs.verdict = Verdict{Code: VC(linux.NFT_CONTINUE)}
}

// checkCompatibility implements operation.checkCompatibility.
// Ref: net/netfilter/xt_addrtype.c:addrtype_mt_checkentry_v1()
func (op *compatAddrtypeMatch) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	chain := cCtx.chain
	if !chain.IsBaseChain() {
		return nil
	}
	hook := chain.baseChainInfo.Hook
	if op.info.limitIfaceOut && (hook == stack.NFPrerouting || hook == stack.NFInput) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "output interface limitation not valid in PREROUTING and INPUT")
	}
	if op.info.limitIfaceIn && (hook == stack.NFPostrouting || hook == stack.NFOutput) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "input interface limitation not valid in POSTROUTING and OUTPUT")
	}
	return nil
}

// deepCopy implements operation.deepCopy.
func (op *compatAddrtypeMatch) deepCopy() operation {
	opCopy := *op
	opCopy.infoData = append([]byte(nil), op.infoData...)
	return &opCopy
}

// updateReferences implements operation.updateReferences.
func (op *compatAddrtypeMatch) updateReferences(_ *Table, _ *Table, _ operation) {}

// destroy implements operation.destroy.
func (op *compatAddrtypeMatch) destroy() {}

// GetExprName implements operation.GetExprName.
func (op *compatAddrtypeMatch) GetExprName() string {
	return OpTypeMatch.String()
}

// Dump implements operation.Dump.
// Ref: net/netfilter/nft_compat.c:__nft_match_dump()
func (op *compatAddrtypeMatch) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttrString(linux.NFTA_MATCH_NAME, MatchAddrtype)
	m.PutAttr(linux.NFTA_MATCH_REV, nlmsg.PutU32(op.revision))
	if len(op.infoData) > 0 {
		m.PutAttr(linux.NFTA_MATCH_INFO, primitive.AsByteSlice(op.infoData))
	}
	return m.Buffer(), nil
}

var routeToXTAddrType = [linux.RTN_XRESOLVE + 1]uint16{
	linux.RTN_UNSPEC:      linux.XT_ADDRTYPE_UNSPEC,
	linux.RTN_UNICAST:     linux.XT_ADDRTYPE_UNICAST,
	linux.RTN_LOCAL:       linux.XT_ADDRTYPE_LOCAL,
	linux.RTN_BROADCAST:   linux.XT_ADDRTYPE_BROADCAST,
	linux.RTN_ANYCAST:     linux.XT_ADDRTYPE_ANYCAST,
	linux.RTN_MULTICAST:   linux.XT_ADDRTYPE_MULTICAST,
	linux.RTN_BLACKHOLE:   linux.XT_ADDRTYPE_BLACKHOLE,
	linux.RTN_UNREACHABLE: linux.XT_ADDRTYPE_UNREACHABLE,
	linux.RTN_PROHIBIT:    linux.XT_ADDRTYPE_PROHIBIT,
	linux.RTN_THROW:       linux.XT_ADDRTYPE_THROW,
	linux.RTN_NAT:         linux.XT_ADDRTYPE_NAT,
	linux.RTN_XRESOLVE:    linux.XT_ADDRTYPE_XRESOLVE,
}

// routeAddrTypeToXTAddrType converts a Linux RTN_* routing address type to
// XT_ADDRTYPE_* bitmask used by xt_addrtype matches.
// Ref: net/netfilter/xt_addrtype.c
func routeAddrTypeToXTAddrType(rtAddrType uint32) uint16 {
	if rtAddrType < uint32(len(routeToXTAddrType)) {
		return routeToXTAddrType[rtAddrType]
	}
	return linux.XT_ADDRTYPE_UNSPEC
}

// unmarshalRev0 decodes xt_addrtype_info (revision 0) and populates addrTypeMatchInfo.
func (info *addrTypeMatchInfo) unmarshalRev0(infoData []byte) *syserr.AnnotatedError {
	var mtinfo linux.XTAddrtypeInfo
	if len(infoData) < mtinfo.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "addrtype info data too small for revision 0")
	}
	mtinfo.UnmarshalBytes(infoData[:mtinfo.SizeBytes()])
	info.sourceMask = mtinfo.Source
	info.destMask = mtinfo.Dest
	info.checkSrc = mtinfo.Source != 0
	info.invertSrcMatch = mtinfo.InvertSource != 0
	info.checkDst = mtinfo.Dest != 0
	info.invertDstMatch = mtinfo.InvertDest != 0
	return nil
}

// unmarshalRev1 decodes xt_addrtype_info_v1 (revision 1) and populates addrTypeMatchInfo.
func (info *addrTypeMatchInfo) unmarshalRev1(infoData []byte) *syserr.AnnotatedError {
	var mtinfo linux.XTAddrtypeInfoV1
	if len(infoData) < mtinfo.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "addrtype info data too small for revision 1")
	}
	mtinfo.UnmarshalBytes(infoData[:mtinfo.SizeBytes()])
	if mtinfo.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0 && mtinfo.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0 {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "both incoming and outgoing interface limitation cannot be selected")
	}
	info.sourceMask = mtinfo.Source
	info.destMask = mtinfo.Dest
	info.checkSrc = mtinfo.Source != 0
	info.invertSrcMatch = mtinfo.Flags&linux.XT_ADDRTYPE_INVERT_SOURCE != 0
	info.limitIfaceIn = mtinfo.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0
	info.checkDst = mtinfo.Dest != 0
	info.invertDstMatch = mtinfo.Flags&linux.XT_ADDRTYPE_INVERT_DEST != 0
	info.limitIfaceOut = mtinfo.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0
	return nil
}

const (
	addrtypeRevision0   = 0
	addrtypeRevision1   = 1
	addrtypeMaxRevision = addrtypeRevision1
)

// lookupAddrtypeRevision checks if an addrtype match revision is supported
// and returns the best revision.
// Ref: net/netfilter/x_tables.c:xt_find_revision
func lookupAddrtypeRevision(rev uint32, family stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	if family != stack.IP && family != stack.IP6 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("addrtype match not supported for family %v", family))
	}
	if rev == addrtypeRevision0 && family != stack.IP {
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, "addrtype revision 0 only supported for IPv4")
	}
	if rev > addrtypeMaxRevision {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("addrtype revision %d not supported", rev))
	}
	return addrtypeMaxRevision, nil
}

// parseAddrtypeMatch parses xtables attribute payload to addrTypeMatchInfo Op.
// Ref: net/netfilter/xt_addrtype.c:addrtype_mt_reg
func parseAddrtypeMatch(tab *Table, rev uint32, infoData []byte) (*addrTypeMatchInfo, *syserr.AnnotatedError) {
	// Inet is not supported by addrtype match.
	if tab.GetAddressFamily() != stack.IP && tab.GetAddressFamily() != stack.IP6 {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("addrtype match not supported for address family: %v", tab.GetAddressFamily()))
	}
	info := &addrTypeMatchInfo{}
	var err *syserr.AnnotatedError
	switch rev {
	case addrtypeRevision0:
		if tab.GetAddressFamily() != stack.IP {
			return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, "addrtype revision 0 is only supported for IPv4")
		}
		err = info.unmarshalRev0(infoData)
	case addrtypeRevision1:
		err = info.unmarshalRev1(infoData)
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("addrtype revision %d not supported", rev))
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}
