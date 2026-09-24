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
	// TableNameNAT is the NAT table name.
	TableNameNAT = "nat"

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

// ProcessCompatMessage handles netfilter compatibility messages (NFNL_SUBSYS_NFT_COMPAT).
// Matches Linux net/netfilter/nft_compat.c:nfnl_compat_get_rcu
func (nf *NFTables) ProcessCompatMessage(hdr linux.NetlinkMessageHeader, ms *nlmsg.MessageSet, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily) *syserr.AnnotatedError {
	if family != stack.IP && family != stack.IP6 {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unsupported protocol %v", family))
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

	var bestRev uint32
	var err *syserr.AnnotatedError
	if isTarget == 1 {
		bestRev, err = lookupCompatTargetRevision(name, rev, family)
	} else {
		bestRev, err = lookupCompatMatchRevision(name, rev, family)
	}
	if err != nil {
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
	m.PutAttr(linux.NFTA_COMPAT_REV, nlmsg.PutU32(bestRev))
	m.PutAttr(linux.NFTA_COMPAT_TYPE, nlmsg.PutU32(isTarget))

	return nil
}
