// Copyright 2023 The gVisor Authors.
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

package netfilter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func init() {
	registerMatchMaker(ownerMarshalerV1{})
}

// ownerMarshalerV1 implements matchMaker for owner matching.
type ownerMarshalerV1 struct{}

// name implements matchMaker.name.
func (ownerMarshalerV1) name() string {
	return matcherNameOwner
}

func (ownerMarshalerV1) revision() uint8 {
	return 1
}

// marshal implements matchMaker.marshal.
func (ownerMarshalerV1) marshal(mr matcher) []byte {
	matcher := mr.(*OwnerMatcherV1)
	ownerInfo := linux.XTOwnerMatchInfo{
		UIDMin: uint32(matcher.uid),
		UIDMax: uint32(matcher.uid),
		GIDMin: uint32(matcher.gid),
		GIDMax: uint32(matcher.gid),
	}

	// Support for UID and GID match.
	if matcher.matchUID {
		ownerInfo.Match |= linux.XT_OWNER_UID
	}
	if matcher.matchGID {
		ownerInfo.Match |= linux.XT_OWNER_GID
	}
	if matcher.invertUID {
		ownerInfo.Invert |= linux.XT_OWNER_UID
	}
	if matcher.invertGID {
		ownerInfo.Invert |= linux.XT_OWNER_GID
	}
	buf := marshal.Marshal(&ownerInfo)
	return marshalEntryMatch(matcherNameOwner, buf)
}

// unmarshal implements matchMaker.unmarshal.
func (ownerMarshalerV1) unmarshal(mapper IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfXTOwnerMatchInfo {
		return nil, fmt.Errorf("buf has insufficient size for owner match: %d", len(buf))
	}

	// For alignment reasons, the match's total size may
	// exceed what's strictly necessary to hold matchData.
	var matchData linux.XTOwnerMatchInfo
	matchData.UnmarshalUnsafe(buf)
	nflog("parsed XTOwnerMatchInfo: %+v", matchData)

	if matchData.UIDMin != matchData.UIDMax {
		nflog("owner v1 doesn't support differing UID min/max")
	}
	if matchData.GIDMin != matchData.GIDMax {
		nflog("owner v1 doesn't support differing GID min/max")
	}
	owner := OwnerMatcherV1{
		uid:       mapper.MapToKUID(auth.UID(matchData.UIDMin)),
		gid:       mapper.MapToKGID(auth.GID(matchData.GIDMin)),
		matchUID:  matchData.Match&linux.XT_OWNER_UID != 0,
		matchGID:  matchData.Match&linux.XT_OWNER_GID != 0,
		invertUID: matchData.Invert&linux.XT_OWNER_UID != 0,
		invertGID: matchData.Invert&linux.XT_OWNER_GID != 0,
	}
	return &owner, nil
}

// OwnerMatcherV1 matches against a UID and/or GID.
type OwnerMatcherV1 struct {
	uid       auth.KUID
	gid       auth.KGID
	matchUID  bool
	matchGID  bool
	invertUID bool
	invertGID bool
}

// name implements matcher.name.
func (*OwnerMatcherV1) name() string {
	return matcherNameOwner
}

func (*OwnerMatcherV1) revision() uint8 {
	return 1
}

// Match implements Matcher.Match.
func (om *OwnerMatcherV1) Match(hook stack.Hook, pkt stack.PacketBufferPtr, _, _ string) (bool, bool) {
	// Support only for OUTPUT chain.
	if hook != stack.Output {
		return false, true
	}

	// If the packet owner is not set, drop the packet.
	if pkt.Owner == nil {
		return false, true
	}

	var matches bool
	// Check for UID match.
	if om.matchUID {
		if auth.KUID(pkt.Owner.KUID()) == om.uid {
			matches = true
		}
		if matches == om.invertUID {
			return false, false
		}
	}

	// Check for GID match.
	if om.matchGID {
		matches = false
		if auth.KGID(pkt.Owner.KGID()) == om.gid {
			matches = true
		}
		if matches == om.invertGID {
			return false, false
		}
	}

	return true, false
}
