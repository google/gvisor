// Copyright 2020 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
)

const matcherNameOwner = "owner"

func init() {
	registerMatchMaker(ownerMarshaler{})
}

// ownerMarshaler implements matchMaker for owner matching.
type ownerMarshaler struct{}

// name implements matchMaker.name.
func (ownerMarshaler) name() string {
	return matcherNameOwner
}

// marshal implements matchMaker.marshal.
func (ownerMarshaler) marshal(mr stack.Matcher) []byte {
	matcher := mr.(*OwnerMatcher)
	iptOwnerInfo := linux.IPTOwnerInfo{
		UID: matcher.uid,
		GID: matcher.gid,
	}

	// Support for UID match.
	// TODO(gvisor.dev/issue/170): Need to support gid match.
	if matcher.matchUID {
		iptOwnerInfo.Match = linux.XT_OWNER_UID
	} else if matcher.matchGID {
		panic("GID match is not supported.")
	} else {
		panic("UID match is not set.")
	}

	buf := make([]byte, 0, linux.SizeOfIPTOwnerInfo)
	return marshalEntryMatch(matcherNameOwner, binary.Marshal(buf, usermem.ByteOrder, iptOwnerInfo))
}

// unmarshal implements matchMaker.unmarshal.
func (ownerMarshaler) unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfIPTOwnerInfo {
		return nil, fmt.Errorf("buf has insufficient size for owner match: %d", len(buf))
	}

	// For alignment reasons, the match's total size may
	// exceed what's strictly necessary to hold matchData.
	var matchData linux.IPTOwnerInfo
	binary.Unmarshal(buf[:linux.SizeOfIPTOwnerInfo], usermem.ByteOrder, &matchData)
	nflog("parseMatchers: parsed IPTOwnerInfo: %+v", matchData)

	if matchData.Invert != 0 {
		return nil, fmt.Errorf("invert flag is not supported for owner match")
	}

	// Support for UID match.
	// TODO(gvisor.dev/issue/170): Need to support gid match.
	if matchData.Match&linux.XT_OWNER_UID != linux.XT_OWNER_UID {
		return nil, fmt.Errorf("owner match is only supported for uid")
	}

	// Check Flags.
	var owner OwnerMatcher
	owner.uid = matchData.UID
	owner.gid = matchData.GID
	owner.matchUID = true

	return &owner, nil
}

type OwnerMatcher struct {
	uid      uint32
	gid      uint32
	matchUID bool
	matchGID bool
	invert   uint8
}

// Name implements Matcher.Name.
func (*OwnerMatcher) Name() string {
	return matcherNameOwner
}

// Match implements Matcher.Match.
func (om *OwnerMatcher) Match(hook stack.Hook, pkt stack.PacketBuffer, interfaceName string) (bool, bool) {
	// Support only for OUTPUT chain.
	// TODO(gvisor.dev/issue/170): Need to support for POSTROUTING chain also.
	if hook != stack.Output {
		return false, true
	}

	// If the packet owner is not set, drop the packet.
	// Support for uid match.
	// TODO(gvisor.dev/issue/170): Need to support gid match.
	if pkt.Owner == nil || !om.matchUID {
		return false, true
	}

	// TODO(gvisor.dev/issue/170): Need to add tests to verify
	// drop rule when packet UID does not match owner matcher UID.
	if pkt.Owner.UID() != om.uid {
		return false, false
	}

	return true, false
}
