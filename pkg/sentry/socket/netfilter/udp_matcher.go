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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
)

const matcherNameUDP = "udp"

func init() {
	registerMatchMaker(udpMarshaler{})
}

// udpMarshaler implements matchMaker for UDP matching.
type udpMarshaler struct{}

// name implements matchMaker.name.
func (udpMarshaler) name() string {
	return matcherNameUDP
}

// marshal implements matchMaker.marshal.
func (udpMarshaler) marshal(mr stack.Matcher) []byte {
	matcher := mr.(*UDPMatcher)
	xtudp := linux.XTUDP{
		SourcePortStart:      matcher.sourcePortStart,
		SourcePortEnd:        matcher.sourcePortEnd,
		DestinationPortStart: matcher.destinationPortStart,
		DestinationPortEnd:   matcher.destinationPortEnd,
	}
	buf := make([]byte, 0, linux.SizeOfXTUDP)
	return marshalEntryMatch(matcherNameUDP, binary.Marshal(buf, usermem.ByteOrder, xtudp))
}

// unmarshal implements matchMaker.unmarshal.
func (udpMarshaler) unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfXTUDP {
		return nil, fmt.Errorf("buf has insufficient size for UDP match: %d", len(buf))
	}

	// For alignment reasons, the match's total size may exceed what's
	// strictly necessary to hold matchData.
	var matchData linux.XTUDP
	binary.Unmarshal(buf[:linux.SizeOfXTUDP], usermem.ByteOrder, &matchData)
	nflog("parseMatchers: parsed XTUDP: %+v", matchData)

	if matchData.InverseFlags != 0 {
		return nil, fmt.Errorf("unsupported UDP matcher inverse flags set")
	}

	if filter.Protocol != header.UDPProtocolNumber {
		return nil, fmt.Errorf("UDP matching is only valid for protocol %d.", header.UDPProtocolNumber)
	}

	return &UDPMatcher{
		sourcePortStart:      matchData.SourcePortStart,
		sourcePortEnd:        matchData.SourcePortEnd,
		destinationPortStart: matchData.DestinationPortStart,
		destinationPortEnd:   matchData.DestinationPortEnd,
	}, nil
}

// UDPMatcher matches UDP packets and their headers. It implements Matcher.
type UDPMatcher struct {
	sourcePortStart      uint16
	sourcePortEnd        uint16
	destinationPortStart uint16
	destinationPortEnd   uint16
}

// Name implements Matcher.Name.
func (*UDPMatcher) Name() string {
	return matcherNameUDP
}

// Match implements Matcher.Match.
func (um *UDPMatcher) Match(hook stack.Hook, pkt stack.PacketBuffer, interfaceName string) (bool, bool) {
	netHeader := header.IPv4(pkt.NetworkHeader)

	// TODO(gvisor.dev/issue/170): Proto checks should ultimately be moved
	// into the stack.Check codepath as matchers are added.
	if netHeader.TransportProtocol() != header.UDPProtocolNumber {
		return false, false
	}

	// We dont't match fragments.
	if frag := netHeader.FragmentOffset(); frag != 0 {
		if frag == 1 {
			return false, true
		}
		return false, false
	}

	// Now we need the transport header. However, this may not have been set
	// yet.
	// TODO(gvisor.dev/issue/170): Parsing the transport header should
	// ultimately be moved into the stack.Check codepath as matchers are
	// added.
	var udpHeader header.UDP
	if pkt.TransportHeader != nil {
		udpHeader = header.UDP(pkt.TransportHeader)
	} else {
		// The UDP header hasn't been parsed yet. We have to do it here.
		if len(pkt.Data.First()) < header.UDPMinimumSize {
			// There's no valid UDP header here, so we hotdrop the
			// packet.
			return false, true
		}
		udpHeader = header.UDP(pkt.Data.First())
	}

	// Check whether the source and destination ports are within the
	// matching range.
	if sourcePort := udpHeader.SourcePort(); sourcePort < um.sourcePortStart || um.sourcePortEnd < sourcePort {
		return false, false
	}
	if destinationPort := udpHeader.DestinationPort(); destinationPort < um.destinationPortStart || um.destinationPortEnd < destinationPort {
		return false, false
	}

	return true, false
}
