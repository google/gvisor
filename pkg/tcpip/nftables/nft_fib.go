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

package nftables

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fib is an operation that queries the routing table.
type fib struct {
	result  int
	flags   uint32
	dregIdx int
}

// fibIPv4AddrRouteType determines the route type of the given IPv4 address.
func fibIPv4AddrRouteType(st *stack.Stack, addr tcpip.Address, nicID tcpip.NICID, rt *stack.Route) uint32 {
	switch {
	case addr == header.IPv4Any || addr == header.IPv4Broadcast:
		return uint32(linux.RTN_BROADCAST)
	case header.IsV4MulticastAddress(addr):
		return uint32(linux.RTN_MULTICAST)
	case st.IsSubnetBroadcast(nicID, header.IPv4ProtocolNumber, addr):
		return uint32(linux.RTN_BROADCAST)
	case st.CheckLocalAddress(0 /*nicID*/, header.IPv4ProtocolNumber, addr) != 0:
		// Pass 0 as NICID otherwise the CheckLocalAddress will always return RTN_LOCAL.
		return uint32(linux.RTN_LOCAL)
	case rt != nil:
		return uint32(linux.RTN_UNICAST)
	default:
		return uint32(linux.RTN_UNREACHABLE)
	}
}

// fibIPv6AddrRouteType determines the route type of the given IPv6 address.
func fibIPv6AddrRouteType(st *stack.Stack, addr tcpip.Address, nicID tcpip.NICID, rt *stack.Route) uint32 {
	switch {
	case header.IsV6MulticastAddress(addr):
		return uint32(linux.RTN_MULTICAST)
	case addr == header.IPv6Any:
		// Matches Linux [net/ipv6/netfilter/nft_fib_ipv6.c]:[__nft_fib6_eval_type]()
		return uint32(linux.RTN_UNSPEC)
	case st.CheckLocalAddress(0 /*nicID*/, header.IPv6ProtocolNumber, addr) != 0:
		// Pass 0 as NICID otherwise the CheckLocalAddress will always return RTN_LOCAL.
		return uint32(linux.RTN_LOCAL)
	case rt != nil:
		return uint32(linux.RTN_UNICAST)
	default:
		return uint32(linux.RTN_UNREACHABLE)
	}
}

// fibGetAddrRouteType determines the route type of the given address.
// nicID represents the constraint interface ID.
// rt is the route to 'addr' (if one was found).
func fibGetAddrRouteType(netProto tcpip.NetworkProtocolNumber, st *stack.Stack, addr tcpip.Address, nicID tcpip.NICID, rt *stack.Route) uint32 {
	switch netProto {
	case header.IPv4ProtocolNumber:
		return fibIPv4AddrRouteType(st, addr, nicID, rt)
	case header.IPv6ProtocolNumber:
		return fibIPv6AddrRouteType(st, addr, nicID, rt)
	default:
		return uint32(linux.RTN_UNSPEC)
	}
}

// Ref: net/netfilter/nft_fib.c:nft_fib_store_result()
func (op *fib) storeResult(regs *registerSet, nicID tcpip.NICID, st *stack.Stack) {
	// Just set the boolean result if the flag is set.
	if op.flags&linux.NFTA_FIB_F_PRESENT != 0 {
		if nicID != 0 {
			regs.data[op.dregIdx] = uint8(1)
		} else {
			regs.data[op.dregIdx] = uint8(0)
		}
		return
	}

	switch op.result {
	case linux.NFT_FIB_RESULT_OIF:
		binary.NativeEndian.PutUint32(regs.data[op.dregIdx:], uint32(nicID))
	case linux.NFT_FIB_RESULT_OIFNAME:
		name := st.FindNICNameFromID(nicID)
		startIdx, endIdx := op.dregIdx, op.dregIdx+linux.IFNAMSIZ
		copy(regs.data[startIdx:endIdx], name)
	}
}

func fibValidatePktHeader(pkt *stack.PacketBuffer) bool {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		hdr := pkt.NetworkHeader().Slice()
		if len(hdr) < header.IPv4MinimumSize {
			return false
		}
	case header.IPv6ProtocolNumber:
		hdr := pkt.NetworkHeader().Slice()
		if len(hdr) < header.IPv6MinimumSize {
			return false
		}
	}
	return true
}

func fibGetSrcDstAddr(pkt *stack.PacketBuffer) (tcpip.Address, tcpip.Address, bool) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		hdr := pkt.NetworkHeader().Slice()
		iph := header.IPv4(hdr)
		return iph.SourceAddress(), iph.DestinationAddress(), true
	case header.IPv6ProtocolNumber:
		hdr := pkt.NetworkHeader().Slice()
		iph := header.IPv6(hdr)
		return iph.SourceAddress(), iph.DestinationAddress(), true
	}
	return tcpip.Address{}, tcpip.Address{}, false
}

// fibGetOrFindRoute returns a route from the stack. If the route is found in the
// evalCtx, it is returned directly. Otherwise, the route is found using
// FindRoute.
func fibGetOrFindRoute(evalCtx opEvalCtx, srcAddr, dstAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, nicID tcpip.NICID, dAddr bool) (rt *stack.Route, release func(), err tcpip.Error) {
	if dAddr && evalCtx.route != nil {
		return evalCtx.route, func() {}, nil
	}
	rt, err = evalCtx.nftState.stack.FindRoute(nicID, srcAddr, dstAddr, netProto, false)
	if err != nil {
		return nil, func() {}, err
	}
	return rt, rt.Release, nil
}

// Ref: net/ipv[4|6]/netfilter/nft_fib_ipv[4|6].c]:nft_fib[4|6]_eval()
func (op *fib) evaluateOIF(regs *registerSet, evalCtx opEvalCtx) {
	hook := evalCtx.hook
	pkt := evalCtx.pkt
	st := evalCtx.nftState.stack
	if hook == stack.NFPrerouting || hook == stack.NFInput || hook == stack.NFIngress {
		nic, err := st.GetNICByID(pkt.InputNICID)
		if err == nil && nic.IsLoopback() {
			op.storeResult(regs, pkt.InputNICID, st)
			return
		}
	}

	// When:
	// 1. nicID == 0, means no OIF/IIF constraint was specified, and FIB will
	// just deduce and store the interface from the route lookup.
	// 2. nicID != 0, FIB will verify if the calculated route's interface matches
	// this constraint, and only store the result if they match.
	nicID := tcpip.NICID(0)
	if op.flags&linux.NFTA_FIB_F_OIF != 0 {
		if evalCtx.route != nil {
			nicID = evalCtx.route.OutgoingNIC()
		}
	} else if op.flags&linux.NFTA_FIB_F_IIF != 0 {
		nicID = pkt.InputNICID
	}

	if !fibValidatePktHeader(evalCtx.pkt) {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}
	srcAddr, dstAddr, ok := fibGetSrcDstAddr(pkt)
	if !ok {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	netProto := pkt.NetworkProtocolNumber
	switch netProto {
	case header.IPv4ProtocolNumber:
		if srcAddr == header.IPv4Any {
			if dstAddr == header.IPv4Broadcast || header.IsV4LinkLocalMulticastAddress(dstAddr) {
				op.storeResult(regs, pkt.NICID, st)
				return
			}
		}

	case header.IPv6ProtocolNumber:
		if fibIPv6SkipICMP(pkt, srcAddr, dstAddr) {
			op.storeResult(regs, pkt.InputNICID, st)
			return
		}
	}

	dAddr := op.flags&linux.NFTA_FIB_F_DADDR != 0
	if !dAddr {
		srcAddr, dstAddr = dstAddr, srcAddr
	} else {
		if evalCtx.hook == stack.NFForward && op.flags&linux.NFTA_FIB_F_IIF != 0 {
			log.Warningf("fib FORWARD hook with IIF flag is not fully supported.")
			// TODO: b/530282592 - In Linux, if hook is FORWARD and IIF is set,
			// the lookup's input interface is set to the output interface.
			// However, gVisor's FindRoute does not consider the input interface
			// for finding routes.
		}
	}
	if netProto == header.IPv4ProtocolNumber {
		// don't try to find route from mcast/bcast/zeronet.
		// Ref: net/ipv4/netfilter/nft_fib_ipv4.c:get_saddr()
		if srcAddr == header.IPv4Broadcast || header.IsV4MulticastAddress(srcAddr) ||
			// Ref: include/linux/in.h:ipv4_is_zeronet()
			srcAddr == header.IPv4Any {
			srcAddr = tcpip.Address{}
		}
	}
	addr := dstAddr

	// Set the default result to 0 now and only set the regs based on the
	// the result of route lookup.
	// Linux had a CVE-2026-53134 related to not clearing the register.
	if op.result == linux.NFT_FIB_RESULT_OIFNAME {
		startIdx, endIdx := op.dregIdx, op.dregIdx+linux.IFNAMSIZ
		clear(regs.data[startIdx:endIdx])
	} else {
		binary.NativeEndian.PutUint32(regs.data[op.dregIdx:], uint32(0))
	}

	rt, release, err := fibGetOrFindRoute(evalCtx, srcAddr, dstAddr, netProto, nicID, dAddr)
	defer release()
	if err != nil {
		return
	}

	addrType := fibGetAddrRouteType(netProto, st, addr, nicID, rt)
	if addrType == linux.RTN_LOCAL {
		return
	}

	// Just need to set the result to NICID if it is not 0.
	if nicID == 0 {
		op.storeResult(regs, rt.NICID(), st)
		return
	}
	if rt.OutgoingNIC() == nicID {
		op.storeResult(regs, nicID, st)
		return
	}
}

// fibIPv6SkipICMP returns true if FIB should skip the route lookup.
// Ref: net/ipv6/netfilter/nft_fib_ipv6.c:nft_fib_v6_skip_icmpv6()
func fibIPv6SkipICMP(pkt *stack.PacketBuffer, saddr, daddr tcpip.Address) bool {
	if pkt.TransportProtocolNumber != header.ICMPv6ProtocolNumber {
		return false
	}
	if saddr != header.IPv6Any {
		return false
	}
	return header.IsV6LinkLocalUnicastAddress(daddr) || header.IsV6LinkLocalMulticastAddress(daddr)
}

// Ref: net/ipv4/netfilter/nft_fib_ipv[4|6].c:nft_fib[4|6]_eval_type()
func (op *fib) evaluateAddrType(regs *registerSet, evalCtx opEvalCtx) {
	pkt := evalCtx.pkt
	if !fibValidatePktHeader(pkt) {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	srcAddr, dstAddr, ok := fibGetSrcDstAddr(pkt)
	if !ok {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	dAddr := op.flags&linux.NFTA_FIB_F_DADDR != 0
	if !dAddr {
		srcAddr, dstAddr = dstAddr, srcAddr
	}
	addr := dstAddr

	st := evalCtx.nftState.stack
	netProto := pkt.NetworkProtocolNumber

	nicID := tcpip.NICID(0)
	if op.flags&linux.NFTA_FIB_F_IIF != 0 {
		nicID = pkt.InputNICID
	} else if op.flags&linux.NFTA_FIB_F_OIF != 0 {
		if evalCtx.route != nil {
			nicID = evalCtx.route.OutgoingNIC()
		}
	}

	// Find route to determine address type.
	rt, release, _ := fibGetOrFindRoute(evalCtx, srcAddr, dstAddr, netProto, nicID, dAddr)
	defer release()

	addrType := fibGetAddrRouteType(netProto, st, addr, nicID, rt)
	binary.NativeEndian.PutUint32(regs.data[op.dregIdx:], addrType)
}

// evaluate implements operation.evaluate.
// Ref: net/netfilter/nft_fib.c:nft_fib_eval()
func (op *fib) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	switch op.result {
	case linux.NFT_FIB_RESULT_ADDRTYPE:
		op.evaluateAddrType(regs, evalCtx)
	default:
		op.evaluateOIF(regs, evalCtx)
	}
}

// GetExprName implements operation's ExprName interface.
func (op *fib) GetExprName() string {
	return OpTypeFIB.String()
}

// Dump implements operation's Dump interface.
func (op *fib) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_FIB_DREG, formatRegIdxForDump(op.dregIdx))
	m.PutAttr(linux.NFTA_FIB_RESULT, nlmsg.PutU32(uint32(op.result)))
	m.PutAttr(linux.NFTA_FIB_FLAGS, nlmsg.PutU32(op.flags))
	return m.Buffer(), nil
}

// deepCopy implements operation's deepCopy interface.
func (op *fib) deepCopy() operation {
	opCopy := &fib{}
	opCopy.result = op.result
	opCopy.flags = op.flags
	opCopy.dregIdx = op.dregIdx
	return opCopy
}

// updateReferences implements operation.updateReferences.
func (op *fib) updateReferences(table *Table, sourceTable *Table, sourceOp operation) {}

// checkCompatibility implements operation.checkCompatibility.
// Ref: net/netfilter/nft_fib.c:nft_fib_validate()
func (op *fib) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	c := cCtx.chain
	if c == nil {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "cannot validate fib operation on a rule without a chain")
	}
	if c.baseChainInfo == nil {
		// Accept case.
		return nil
	}
	hook := c.baseChainInfo.Hook
	switch op.result {
	case linux.NFT_FIB_RESULT_OIF, linux.NFT_FIB_RESULT_OIFNAME:
		switch hook {
		case stack.NFPrerouting, stack.NFInput, stack.NFForward:
			return nil
		}
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib result OIF/OIFNAME only valid in PREROUTING, INPUT, FORWARD")
	case linux.NFT_FIB_RESULT_ADDRTYPE:
		if op.flags&linux.NFTA_FIB_F_IIF != 0 {
			switch hook {
			case stack.NFPrerouting, stack.NFInput, stack.NFForward:
				return nil
			}
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib result ADDRTYPE with IIF only valid in PREROUTING, INPUT, FORWARD")
		}
		switch hook {
		case stack.NFInput, stack.NFOutput, stack.NFForward, stack.NFPrerouting, stack.NFPostrouting:
			return nil
		}
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib result ADDRTYPE without IIF/OIF only valid in INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING")
	}
	return nil
}

// newFIB creates a new fib operation.
// Ref: net/netfilter/nft_fib.c:nft_fib_init()
func newFIB(result int, flags uint32, dreg uint8) (*fib, *syserr.AnnotatedError) {
	if isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(
			syserr.ErrInvalidArgument, "fib operation does not support verdict register as destination register",
		)
	}

	if flags == 0 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib flags cannot be zero")
	}

	if flags&linux.NFTA_FIB_F_MARK != 0 {
		log.Warningf("fib mark flag is not supported for routing lookup in gVisor")
	}

	if (flags & (linux.NFTA_FIB_F_SADDR | linux.NFTA_FIB_F_DADDR)) == (linux.NFTA_FIB_F_SADDR | linux.NFTA_FIB_F_DADDR) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib flags cannot have both SADDR and DADDR")
	}
	if (flags & (linux.NFTA_FIB_F_IIF | linux.NFTA_FIB_F_OIF)) == (linux.NFTA_FIB_F_IIF | linux.NFTA_FIB_F_OIF) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib flags cannot have both IIF and OIF")
	}
	if (flags & (linux.NFTA_FIB_F_SADDR | linux.NFTA_FIB_F_DADDR)) == 0 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "fib flags must have at least SADDR or DADDR")
	}

	resLen := 0
	switch result {
	case linux.NFT_FIB_RESULT_OIF:
		if flags&linux.NFTA_FIB_F_OIF != 0 {
			return nil, syserr.NewAnnotatedError(
				syserr.ErrInvalidArgument,
				"fib result OIF/OIFNAME cannot be used with OIF flag",
			)
		}
		resLen = 4 // size of int
	case linux.NFT_FIB_RESULT_OIFNAME:
		if flags&linux.NFTA_FIB_F_OIF != 0 {
			return nil, syserr.NewAnnotatedError(
				syserr.ErrInvalidArgument,
				"fib result OIF/OIFNAME cannot be used with OIF flag",
			)
		}
		resLen = linux.IFNAMSIZ
	case linux.NFT_FIB_RESULT_ADDRTYPE:
		resLen = 4 // size of uint32
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown fib result: %d", result))
	}

	dataLen := resLen
	dregIdx, err := regNumToIdx(dreg, dataLen)
	if err != nil {
		return nil, err
	}

	return &fib{result: result, flags: flags, dregIdx: dregIdx}, nil
}

const nftFibFlagsAll = linux.NFTA_FIB_F_SADDR | linux.NFTA_FIB_F_DADDR |
	linux.NFTA_FIB_F_MARK | linux.NFTA_FIB_F_IIF | linux.NFTA_FIB_F_OIF |
	linux.NFTA_FIB_F_PRESENT

// Ref: net/netfilter/nft_fib.c:nft_fib_policy
var nftFibPolicy = []NlaPolicy{
	{nlaType: linux.NLA_U32, validator: AttrMaskValidator[uint32](nftFibFlagsAll)},
	{nlaType: linux.NLA_U32},
	{nlaType: linux.NLA_U32},
}

// Ref: net/netfilter/nft_fib.c:nft_fib_init()
func initFIB(tab *Table, exprInfo ExprInfo) (operation, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: nftFibPolicy,
	})
	if err != nil {
		return nil, err
	}
	dreg, ok := AttrNetToHost[uint32](linux.NFTA_FIB_DREG, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_FIB_DREG")
	}
	result, ok := AttrNetToHost[uint32](linux.NFTA_FIB_RESULT, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_FIB_RESULT")
	}
	flags, ok := AttrNetToHost[uint32](linux.NFTA_FIB_FLAGS, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_FIB_FLAGS")
	}
	return newFIB(int(result), flags, uint8(dreg))
}
