// Copyright 2024 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	matcherRevMultiportV1 uint8  = 1
	matcherPfxMultiportV1 string = (matcherNameMultiport + ".1")
)

// multiportMarshalerV1 handles marshalling and
// unmarshalling of "xt_multiport_v1" matchers.
type multiportMarshalerV1 struct{}

// multiportMatcherV1 represents a multiport matcher with
// source and/or destination ports, per-port flags, and an
// inversion flag.
type multiportMatcherV1 struct {
	flags  uint8    // Port match flag (source/destination/either).
	count  uint8    // Number of ports.
	ports  []uint16 // List of ports to match against.
	pflags []uint8  // Per-port flags (for range matches).
	invert bool     // Invert match result.
}

// init registers the "multiportMarshalerV1" with the matcher registry.
func init() {
	registerMatchMaker(multiportMarshalerV1{})
}

// name returns the name of the marshaler.
func (multiportMarshalerV1) name() string {
	return matcherNameMultiport
}

// revision returns the revision number of the marshaler.
func (multiportMarshalerV1) revision() uint8 {
	return matcherRevMultiportV1
}

// marshal converts a "multiportMatcherV1" into its binary representation.
func (multiportMarshalerV1) marshal(mr matcher) []byte {
	m := mr.(*multiportMatcherV1)
	var xtmp linux.XTMultiportV1

	// Set the match criteria flag.
	xtmp.Flags = m.flags

	// Set the count of ports and populate the "Ports" slice.
	xtmp.Count = uint8(len(m.ports))

	// Truncate the "ports" slice to the maximum allowed
	// by "XT_MULTI_PORTS" to prevent out-of-bounds writes.
	if xtmp.Count > linux.XT_MULTI_PORTS {
		xtmp.Count = linux.XT_MULTI_PORTS
	}

	// Copy over the ports, and per-port flags.
	for i := uint8(0); i < xtmp.Count; i++ {
		xtmp.Ports[i] = m.ports[i]
		xtmp.Pflags[i] = m.pflags[i]
	}

	// If the match result is to be inverted.
	if m.invert {
		xtmp.Invert = uint8(1)
	}

	// Marshal the XTMultiportV1 structure into binary format.
	return marshalEntryMatch(matcherNameMultiport, marshal.Marshal(&xtmp))
}

// unmarshal converts binary data into a multiportMatcherV1 instance.
func (multiportMarshalerV1) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	var matchData linux.XTMultiportV1

	nflog("%s: raw XTMultiportV1: %+v", matcherPfxMultiportV1, buf)

	// Check if the buffer has enough data for XTMultiportV1.
	if len(buf) < linux.SizeOfXTMultiportV1 {
		return nil, fmt.Errorf(
			"%s: insufficient data, got %d, want: >= %d",
			matcherPfxMultiportV1,
			len(buf),
			linux.SizeOfXTMultiportV1,
		)
	}

	// Unmarshal the buffer into the XTMultiportV1 structure.
	matchData.UnmarshalUnsafe(buf)
	nflog("%s: parsed XTMultiportV1: %+v", matcherPfxMultiportV1, matchData)

	// Validate the port count.
	if matchData.Count == 0 || matchData.Count > linux.XT_MULTI_PORTS {
		return nil, fmt.Errorf(
			"%s: invalid port count, got %d, want: [1, %d]",
			matcherPfxMultiportV1, matchData.Count, linux.XT_MULTI_PORTS,
		)
	}

	// Extract the list of ports and their
	// corresponding flags from the match data.
	ports := make([]uint16, matchData.Count)
	pflags := make([]uint8, matchData.Count)
	for i := 0; i < int(matchData.Count); i++ {
		ports[i] = matchData.Ports[i]
		pflags[i] = matchData.Pflags[i]
	}

	// Initialize "multiportMatcherV1" with the extracted ports and flags.
	matcher := &multiportMatcherV1{
		flags:  matchData.Flags,
		count:  matchData.Count,
		ports:  ports,
		pflags: pflags,
		invert: (matchData.Invert != 0),
	}

	return matcher, nil
}

// name returns the name of the matcher.
func (multiportMatcherV1) name() string {
	return matcherNameMultiport
}

// revision returns the revision number of the matcher.
func (multiportMatcherV1) revision() uint8 {
	return matcherRevMultiportV1
}

// Match determines if the packet matches any of the specified ports
// and returns true if a match is found. The second boolean returned
// indicates whether the packet should be "hot" dropped, or processed
// with other matchers.
func (m *multiportMatcherV1) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	// Extract source and destination ports from the packet.
	srcPort, dstPort, ok := extractPorts(pkt)
	// The packet does not contain valid transport
	// headers or uses an unsupported protocol.
	if !ok {
		return false, true
	}

	// Iterate through the list of ports to check for a match based on
	// the specified match criteria: source, destination or either.
	i := uint8(0)
	for i < m.count {
		exact := (m.pflags[i] == 0)

		// This is unlikely, but if range match is enabled for the
		// last port in the list, treat it as an exact port match.
		if i == (m.count - 1) {
			exact = true
		}

		if exact {
			// Exact port match.
			if exactPortMatch(m.flags, srcPort, dstPort, m.ports[i]) {
				return (true != m.invert), false
			}

			i++
			continue
		}

		if rangedPortMatch(m.flags, srcPort, dstPort, m.ports[i], m.ports[i+1]) {
			return (true != m.invert), false
		}
		i += 2
	}

	// No match; invert if needed.
	return (false != m.invert), false
}

// rangedPortMatch return true if "srcPort" or "dstPort" are
// the same in the range of "matchPort{Beg,End}" depending on
// the matching criteria specified in "flags".
func rangedPortMatch(flags uint8, srcPort, dstPort, begPort, endPort uint16) bool {
	minPort, maxPort := min(begPort, endPort), max(begPort, endPort)
	srcPortMatch := (srcPort >= minPort) && (srcPort <= maxPort)
	dstPortMatch := (dstPort >= minPort) && (dstPort <= maxPort)

	switch flags {
	case linux.XT_MULTIPORT_SOURCE:
		return srcPortMatch
	case linux.XT_MULTIPORT_DESTINATION:
		return dstPortMatch
	case linux.XT_MULTIPORT_EITHER:
		return srcPortMatch || dstPortMatch
	}

	return false
}
