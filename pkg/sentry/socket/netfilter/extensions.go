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

	// marshal converts from an stack.Matcher to an ABI struct.
	marshal(matcher stack.Matcher) []byte

	// unmarshal converts from the ABI matcher struct to an
	// stack.Matcher.
	unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error)
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

func marshalMatcher(matcher stack.Matcher) []byte {
	matchMaker, ok := matchMakers[matcher.Name()]
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
	buf = binary.Marshal(buf, usermem.ByteOrder, matcher)
	return append(buf, make([]byte, size-len(buf))...)
}

func unmarshalMatcher(match linux.XTEntryMatch, filter stack.IPHeaderFilter, buf []byte) (stack.Matcher, error) {
	matchMaker, ok := matchMakers[match.Name.String()]
	if !ok {
		return nil, fmt.Errorf("unsupported matcher with name %q", match.Name.String())
	}
	return matchMaker.unmarshal(buf, filter)
}
