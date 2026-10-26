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

// This file implements XTables compatibility match dispatcher ("match" extensions)
// for nftables rules via nft-compat. It dispatches to specific match implementations
// like conntrack and addrtype.
//
// Ref: net/netfilter/nft_compat.c

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	tcpudpRevision1   = 1
	tcpudpMaxRevision = tcpudpRevision1
)

// lookupTCPUDPRevision validates if a tcp/udp match revision is supported
// and returns the best revision.
func lookupTCPUDPRevision(name string, rev uint32, family stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	if family != stack.IP && family != stack.IP6 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("%s match not supported for family %v", name, family))
	}
	if rev > tcpudpMaxRevision {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("%s revision %d not supported", name, rev))
	}
	return tcpudpMaxRevision, nil
}

// lookupCompatMatchRevision validates if a match revision is supported and returns the best revision.
// Ref: net/netfilter/nft_compat.c:nfnl_compat_get_rcu, net/netfilter/x_tables.c:xt_find_revision
func lookupCompatMatchRevision(name string, rev uint32, family stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	switch name {
	case MatchAddrtype:
		return lookupAddrtypeRevision(rev, family)
	case MatchConntrack:
		return lookupConntrackRevision(rev, family)
	case MatchTCP, MatchUDP:
		return lookupTCPUDPRevision(name, rev, family)
	default:
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("match extension %s not supported", name))
	}
}

// compatNoopMatch implements pass-through xtables matches like "tcp" and "udp".
// TODO: b/505405732 - Support xt_tcp/xt_udp.
type compatNoopMatch struct {
	// name is the name of the match extension (e.g., "tcp" or "udp").
	name string
	// revision is the match extension revision.
	revision uint32
	// infoData is the raw netlink attribute payload; saved for dump.
	infoData []byte
}

// Ref: net/netfilter/xt_tcpudp.c
func (op *compatNoopMatch) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	regs.verdict = Verdict{Code: VC(linux.NFT_CONTINUE)}
}

// checkCompatibility implements operation.checkCompatibility.
func (op *compatNoopMatch) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

// deepCopy implements operation.deepCopy.
func (op *compatNoopMatch) deepCopy() operation {
	opCopy := *op
	opCopy.infoData = append([]byte(nil), op.infoData...)
	return &opCopy
}

// updateReferences implements operation.updateReferences.
func (op *compatNoopMatch) updateReferences(_ *Table, _ *Table, _ operation) {}

// destroy implements operation.destroy.
func (op *compatNoopMatch) destroy() {}

// GetExprName implements operation.GetExprName.
func (op *compatNoopMatch) GetExprName() string {
	return OpTypeMatch.String()
}

// Dump implements operation.Dump.
// Ref: net/netfilter/nft_compat.c:__nft_match_dump()
func (op *compatNoopMatch) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttrString(linux.NFTA_MATCH_NAME, op.name)
	m.PutAttr(linux.NFTA_MATCH_REV, nlmsg.PutU32(op.revision))
	if len(op.infoData) > 0 {
		m.PutAttr(linux.NFTA_MATCH_INFO, primitive.AsByteSlice(op.infoData))
	}
	return m.Buffer(), nil
}

// matchAttrPolicy defines the NLA policy for Match extensions.
// Ref: net/netfilter/nft_compat.c:nft_match_policy
var matchAttrPolicy = []NlaPolicy{
	linux.NFTA_MATCH_NAME: {nlaType: linux.NLA_NUL_STRING},
	linux.NFTA_MATCH_REV:  {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_MATCH_INFO: {nlaType: linux.NLA_BINARY},
}

// initMatch parses NFTA_MATCH_* netlink attributes and returns the operation.
// Ref: net/netfilter/nft_compat.c:__nft_match_init()
func initMatch(tab *Table, exprInfo ExprInfo) (operation, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: matchAttrPolicy,
	})
	if err != nil {
		return nil, err
	}

	nameAttr, ok := attrs[linux.NFTA_MATCH_NAME]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_MATCH_NAME attribute is not found")
	}
	name := nameAttr.String()

	rev, ok := AttrNetToHost[uint32](linux.NFTA_MATCH_REV, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_MATCH_REV attribute is not found")
	}

	infoAttr, ok := attrs[linux.NFTA_MATCH_INFO]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_MATCH_INFO attribute is not found")
	}
	infoData := []byte(infoAttr)

	switch name {
	case MatchAddrtype:
		addr, err := parseAddrtypeMatch(tab, rev, infoData)
		if err != nil {
			return nil, err
		}
		return &compatAddrtypeMatch{revision: rev, infoData: infoData, info: *addr}, nil
	case MatchConntrack:
		ct, err := parseConntrackMatch(rev, infoData)
		if err != nil {
			return nil, err
		}
		return &compatCTMatch{revision: rev, infoData: infoData, info: *ct}, nil
	case MatchTCP, MatchUDP:
		if tab.GetAddressFamily() != stack.IP && tab.GetAddressFamily() != stack.IP6 {
			return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("%s match not supported for address family: %v", name, tab.GetAddressFamily()))
		}
		if rev > tcpudpMaxRevision {
			return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("%s revision %d not supported", name, rev))
		}
		return &compatNoopMatch{name: name, revision: rev, infoData: infoData}, nil
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("match extension %s not supported", name))
	}
}
