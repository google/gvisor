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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TODO(gvisor.dev/issue/170): The following per-matcher params should be
// supported:
// - Table name
// - Match size
// - User size
// - Hooks
// - Proto
// - Family

// matchMaker knows how to (un)marshal the matcher named name().
type matchMaker interface {
	// name is the matcher name as stored in the xt_entry_match struct.
	name() string

	// marshal converts from a stack.Matcher to an ABI struct.
	marshal(matcher matcher) []byte

	// unmarshal converts from the ABI matcher struct to an
	// stack.Matcher.
	unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error)
}

type matcher interface {
	name() string
}

// matchMakers maps the name of supported matchers to the matchMaker that
// marshals and unmarshals it. It is immutable after package initialization.
var matchMakers = map[string]matchMaker{}

// registermatchMaker should be called by match extensions to register them
// with the netfilter package.
func registerMatchMaker(mm matchMaker) {
	if _, ok := matchMakers[mm.name()]; ok {
		panic(fmt.Sprintf("Multiple matches registered with name %q.", mm.name()))
	}
	matchMakers[mm.name()] = mm
}

func marshalMatcher(mr stack.Matcher) []byte {
	matcher := mr.(matcher)
	matchMaker, ok := matchMakers[matcher.name()]
	if !ok {
		panic(fmt.Sprintf("Unknown matcher of type %T.", matcher))
	}
	return matchMaker.marshal(matcher)
}

// marshalEntryMatch creates a marshalled XTEntryMatch with the given name and
// data appended at the end.
func marshalEntryMatch(name string, data []byte) []byte {
	nflog("marshaling matcher %q", name)

	// We have to pad this struct size to a multiple of 8 bytes.
	size := binary.AlignUp(linux.SizeOfXTEntryMatch+len(data), 8)
	matcher := linux.KernelXTEntryMatch{
		XTEntryMatch: linux.XTEntryMatch{
			MatchSize: uint16(size),
		},
		Data: data,
	}
	copy(matcher.Name[:], name)

	buf := make([]byte, 0, size)
	buf = binary.Marshal(buf, hostarch.ByteOrder, matcher)
	return append(buf, make([]byte, size-len(buf))...)
}

func unmarshalMatcher(match linux.XTEntryMatch, filter stack.IPHeaderFilter, buf []byte) (stack.Matcher, error) {
	matchMaker, ok := matchMakers[match.Name.String()]
	if !ok {
		return nil, fmt.Errorf("unsupported matcher with name %q", match.Name.String())
	}
	return matchMaker.unmarshal(buf, filter)
}

// targetMaker knows how to (un)marshal a target. Once registered,
// marshalTarget and unmarshalTarget can be used.
type targetMaker interface {
	// id uniquely identifies the target.
	id() targetID

	// marshal converts from a target to an ABI struct.
	marshal(target target) []byte

	// unmarshal converts from the ABI matcher struct to a target.
	unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error)
}

// A targetID uniquely identifies a target.
type targetID struct {
	// name is the target name as stored in the xt_entry_target struct.
	name string

	// networkProtocol is the protocol to which the target applies.
	networkProtocol tcpip.NetworkProtocolNumber

	// revision is the version of the target.
	revision uint8
}

// target extends a stack.Target, allowing it to be used with the extension
// system. The sentry only uses targets, never stack.Targets directly.
type target interface {
	stack.Target
	id() targetID
}

// targetMakers maps the targetID of supported targets to the targetMaker that
// marshals and unmarshals it. It is immutable after package initialization.
var targetMakers = map[targetID]targetMaker{}

func targetRevision(name string, netProto tcpip.NetworkProtocolNumber, rev uint8) (uint8, bool) {
	tid := targetID{
		name:            name,
		networkProtocol: netProto,
		revision:        rev,
	}
	if _, ok := targetMakers[tid]; !ok {
		return 0, false
	}

	// Return the highest supported revision unless rev is higher.
	for _, other := range targetMakers {
		otherID := other.id()
		if name == otherID.name && netProto == otherID.networkProtocol && otherID.revision > rev {
			rev = uint8(otherID.revision)
		}
	}
	return rev, true
}

// registerTargetMaker should be called by target extensions to register them
// with the netfilter package.
func registerTargetMaker(tm targetMaker) {
	if _, ok := targetMakers[tm.id()]; ok {
		panic(fmt.Sprintf("multiple targets registered with name %q.", tm.id()))
	}
	targetMakers[tm.id()] = tm
}

func marshalTarget(tgt stack.Target) []byte {
	// The sentry only uses targets, never stack.Targets directly.
	target := tgt.(target)
	targetMaker, ok := targetMakers[target.id()]
	if !ok {
		panic(fmt.Sprintf("unknown target of type %T with id %+v.", target, target.id()))
	}
	return targetMaker.marshal(target)
}

func unmarshalTarget(target linux.XTEntryTarget, filter stack.IPHeaderFilter, buf []byte) (target, *syserr.Error) {
	tid := targetID{
		name:            target.Name.String(),
		networkProtocol: filter.NetworkProtocol(),
		revision:        target.Revision,
	}
	targetMaker, ok := targetMakers[tid]
	if !ok {
		nflog("unsupported target with name %q", target.Name.String())
		return nil, syserr.ErrInvalidArgument
	}
	return targetMaker.unmarshal(buf, filter)
}
