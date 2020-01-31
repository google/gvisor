// Copyright 2019 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
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

// matchMarshaler knows how to (un)marshal the matcher named name().
type matchMarshaler interface {
	// name is the matcher name as stored in the xt_entry_match struct.
	name() string

	// marshal converts from an iptables.Matcher to an ABI struct.
	marshal(matcher iptables.Matcher) []byte

	// unmarshal converts from the ABI matcher struct to an
	// iptables.Matcher.
	unmarshal(buf []byte, filter iptables.IPHeaderFilter) (iptables.Matcher, error)
}

var matchMarshalers = map[string]matchMarshaler{}

// registerMatchMarshaler should be called by match extensions to register them
// with the netfilter package.
func registerMatchMarshaler(mm matchMarshaler) {
	if _, ok := matchMarshalers[mm.name()]; ok {
		panic(fmt.Sprintf("Multiple matches registered with name %q.", mm.name()))
	}
	matchMarshalers[mm.name()] = mm
}

func marshalMatcher(matcher iptables.Matcher) []byte {
	matchMaker, ok := matchMarshalers[matcher.Name()]
	if !ok {
		panic(fmt.Errorf("Unknown matcher of type %T.", matcher))
	}
	return matchMaker.marshal(matcher)
}

// marshalEntryMatch creates a marshalled XTEntryMatch with the given name and
// data appended at the end.
func marshalEntryMatch(name string, data []byte) []byte {
	nflog("marshaling matcher %q", name)

	// We have to pad this struct size to a multiple of 8 bytes.
	size := alignUp(linux.SizeOfXTEntryMatch+len(data), 8)
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

func unmarshalMatcher(match linux.XTEntryMatch, filter iptables.IPHeaderFilter, buf []byte) (iptables.Matcher, error) {
	matchMaker, ok := matchMarshalers[match.Name.String()]
	if !ok {
		return nil, fmt.Errorf("unsupported matcher with name %q", match.Name.String())
	}
	return matchMaker.unmarshal(buf, filter)
}

// alignUp rounds a length up to an alignment. align must be a power of 2.
func alignUp(length int, align uint) int {
	return (length + int(align) - 1) & ^(int(align) - 1)
}
