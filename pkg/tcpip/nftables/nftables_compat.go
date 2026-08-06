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

// This file implements XTables Netlink compatibility frontend
// for nftables rules via nft-compat. It redirects the requests to the
// match or target operations.
//
// Ref: net/netfilter/nft_compat.c

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// XTables (iptables compat) extension names.
const (
	// TargetMASQUERADE is the MASQUERADE xtables target.
	TargetMASQUERADE = "MASQUERADE"
	// TargetSNAT is the SNAT xtables target.
	TargetSNAT = "SNAT"
	// TargetDNAT is the DNAT xtables target.
	TargetDNAT = "DNAT"

	// MatchConntrack is the conntrack xtables match.
	MatchConntrack = "conntrack"
	// MatchAddrtype is the addrtype xtables match.
	MatchAddrtype = "addrtype"
	// MatchTCP is the tcp xtables match.
	MatchTCP = "tcp"
	// MatchUDP is the udp xtables match.
	MatchUDP = "udp"
)

type compatRevisionRange struct {
	minRev uint32
	maxRev uint32
}

var (
	// supportedTargets maps xtables target names to supported revision range.
	supportedTargets = map[string]compatRevisionRange{
		TargetMASQUERADE: {0, 0},
		TargetSNAT:       {0, 2},
		TargetDNAT:       {0, 2},
	}

	// supportedMatches maps xtables match names to supported revision range.
	supportedMatches = map[string]compatRevisionRange{
		MatchConntrack: {1, 3},
		MatchAddrtype:  {0, 1},
		MatchTCP:       {0, 1},
		MatchUDP:       {0, 1},
	}
)

// lookupCompatRevision validates if the requested revision is supported or not.
func lookupCompatRevision(name string, rev uint32, isTarget bool) *syserr.AnnotatedError {
	var r compatRevisionRange
	var ok bool
	if isTarget {
		r, ok = supportedTargets[name]
	} else {
		r, ok = supportedMatches[name]
	}
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("unsupported extension: name=%s, isTarget=%t", name, isTarget))
	}
	if rev < r.minRev || rev > r.maxRev {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("unsupported revision %d for %s, supported range [%d, %d]", rev, name, r.minRev, r.maxRev))
	}
	return nil
}

// ProcessCompatMessage handles netfilter compatibility messages (NFNL_SUBSYS_NFT_COMPAT).
// Matches Linux net/netfilter/nft_compat.c:nfnl_compat_get_rcu
func (nf *NFTables) ProcessCompatMessage(hdr linux.NetlinkMessageHeader, ms *nlmsg.MessageSet, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily) *syserr.AnnotatedError {
	if err := validateAddressFamily(family); err != nil {
		return err
	}

	msgType := hdr.NetFilterMsgType()
	if msgType != linux.NFNL_MSG_COMPAT_GET {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("unsupported message type: %d", msgType))
	}

	nameAttr, ok := attrs[linux.NFTA_COMPAT_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "missing NFTA_COMPAT_NAME attribute")
	}
	name := nameAttr.String()

	rev, ok := AttrNetToHost[uint32](linux.NFTA_COMPAT_REV, attrs)
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "missing or invalid NFTA_COMPAT_REV attribute")
	}

	isTarget, ok := AttrNetToHost[uint32](linux.NFTA_COMPAT_TYPE, attrs)
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid NFTA_COMPAT_TYPE attribute")
	}

	if err := lookupCompatRevision(name, rev, isTarget == 1); err != nil {
		return err
	}

	// Reply with the best revision.
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFT_COMPAT)<<8 | uint16(linux.NFNL_MSG_COMPAT_GET),
		Seq:  hdr.Seq,
	})

	m.Put(&linux.NetFilterGenMsg{
		Family:     uint8(AfProtocol(family)),
		Version:    uint8(linux.NFNETLINK_V0),
		ResourceID: uint16(0),
	})

	m.PutAttrString(linux.NFTA_COMPAT_NAME, name)
	m.PutAttr(linux.NFTA_COMPAT_REV, nlmsg.PutU32(rev))
	m.PutAttr(linux.NFTA_COMPAT_TYPE, nlmsg.PutU32(isTarget))

	return nil
}
