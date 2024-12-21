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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	matcherNameMultiport string = "multiport"
	matcherRevMultiport  uint8  = 0
	matcherPfxMultiport  string = (matcherNameMultiport + ".0")
)

// multiportMarshaler handles marshalling and
// unmarshalling of "xt_multiport" matchers.
type multiportMarshaler struct{}

// multiportMatcher represents a multiport matcher
// with source and/or destination ports.
type multiportMatcher struct {
	flags uint8    // Port match flag (source/destination/either).
	count uint8    // Number of ports.
	ports []uint16 // List of ports to match against.
}

// init registers the "multiportMarshaler" with the matcher registry.
func init() {
	registerMatchMaker(multiportMarshaler{})
}

// name returns the name of the marshaler.
func (multiportMarshaler) name() string {
	return matcherNameMultiport
}

// revision returns the revision number of the marshaler.
func (multiportMarshaler) revision() uint8 {
	return matcherRevMultiport
}

// marshal converts a matcher into its binary representation.
func (multiportMarshaler) marshal(mr matcher) []byte {
	m := mr.(*multiportMatcher)
	var xtmp linux.XTMultiport

	nflog("%s: marshal: XTMultiport: %+v", matcherPfxMultiport, m)

	// Set the match criteria flag.
	xtmp.Flags = m.flags

	// Set the count of ports and populate the "Ports" slice.
	xtmp.Count = uint8(len(m.ports))

	// Truncate the "ports" slice to the maximum allowed
	// by "XT_MULTI_PORTS" to prevent out-of-bounds writes.
	if xtmp.Count > linux.XT_MULTI_PORTS {
		xtmp.Count = linux.XT_MULTI_PORTS
	}

	// Copy over the ports.
	for i := uint8(0); i < xtmp.Count; i++ {
		xtmp.Ports[i] = m.ports[i]
	}

	// Marshal the XTMultiport structure into binary format.
	return marshalEntryMatch(matcherNameMultiport, marshal.Marshal(&xtmp))
}

// unmarshal converts binary data into a multiportMatcher instance.
func (multiportMarshaler) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	var matchData linux.XTMultiport

	nflog("%s: raw: XTMultiport: %+v", matcherPfxMultiport, buf)

	// Check if the buffer has enough data for XTMultiport.
	if len(buf) < linux.SizeOfXTMultiport {
		return nil, fmt.Errorf(
			"%s: insufficient data, got %d, want: >= %d",
			matcherPfxMultiport,
			len(buf),
			linux.SizeOfXTMultiport,
		)
	}

	// Unmarshal the buffer into the XTMultiport structure.
	matchData.UnmarshalUnsafe(buf)
	nflog("%s: parsed XTMultiport: %+v", matcherPfxMultiport, matchData)

	// Validate the port count.
	if matchData.Count == 0 || matchData.Count > linux.XT_MULTI_PORTS {
		return nil, fmt.Errorf(
			"%s: invalid port count, got %d, want: [1, %d]",
			matcherPfxMultiport, matchData.Count, linux.XT_MULTI_PORTS,
		)
	}

	// Extract the list of ports from the match data.
	ports := make([]uint16, matchData.Count)
	for i := 0; i < int(matchData.Count); i++ {
		ports[i] = matchData.Ports[i]
	}

	// Initialize "multiportMatcher" with the extracted ports.
	matcher := &multiportMatcher{
		flags: matchData.Flags,
		count: matchData.Count,
		ports: ports,
	}

	return matcher, nil
}

// name returns the name of the matcher.
func (multiportMatcher) name() string {
	return matcherNameMultiport
}

// revision returns the revision number of the matcher.
func (multiportMatcher) revision() uint8 {
	return matcherRevMultiport
}

// Match determines if the packet matches any of the specified ports
// and returns true if a match is found. The second boolean returned
// indicates whether the packet should be "hot" dropped, or processed
// with other matchers.
func (m *multiportMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	// Extract source and destination ports from the packet.
	srcPort, dstPort, ok := extractPorts(pkt)
	// The packet does not contain valid transport
	// headers or uses an unsupported protocol.
	if !ok {
		return false, true
	}

	// Iterate through the list of ports to check for a match based on
	// the specified match criteria: source, destination or either.
	for i := uint8(0); i < m.count; i++ {
		if exactPortMatch(m.flags, srcPort, dstPort, m.ports[i]) {
			return true, false
		}
	}

	// No match.
	return false, false
}

// extractTransportHeaderPorts is a helper routine that extracts
// the source and destination ports from the provided transport
// header based on the specified transport protocol. It supports
// TCP and UDP protocols and returns the source port, destination
// port, and a boolean indicating whether the extraction was
// successful. If the protocol is unsupported or the transport
// header is too short, it returns (0, 0, false).
func extractTransportHeaderPorts(hdr []byte, prot tcpip.TransportProtocolNumber) (uint16, uint16, bool) {
	switch prot {
	case header.TCPProtocolNumber:
		// Ensure the TCP header has the minimum required length.
		if len(hdr) < header.TCPMinimumSize {
			return 0, 0, false
		}
		// Extract and return the source and destination ports.
		tcpHdr := header.TCP(hdr)
		return tcpHdr.SourcePort(), tcpHdr.DestinationPort(), true

	case header.UDPProtocolNumber:
		// Similar to TCP.
		if len(hdr) < header.UDPMinimumSize {
			return 0, 0, false
		}
		udpHdr := header.UDP(hdr)
		return udpHdr.SourcePort(), udpHdr.DestinationPort(), true

	default:
		// Unsupported transport protocol; cannot extract ports.
		return 0, 0, false
	}
}

// extractPorts extracts the source and destination ports from the given
// packet buffer. It supports both IPv4 and IPv6 packets and handles TCP
// and UDP transport protocols. It returns the source port, destination
// port, and a boolean indicating success. If the packet does not contain
// enough data or uses an unsupported protocol, it returns (0, 0, false).
func extractPorts(pkt *stack.PacketBuffer) (uint16, uint16, bool) {
	// Retrieve the transport header (TCP/UDP) from the packet buffer.
	transportHdr := pkt.TransportHeader().Slice()

	// Determine the network protocol.
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		// Extract the IPv4 header from the network header
		// slice, then the transport protocol from it.
		ipv4 := header.IPv4(pkt.NetworkHeader().Slice())
		prot := ipv4.TransportProtocol()
		return extractTransportHeaderPorts(transportHdr, prot)

	case header.IPv6ProtocolNumber:
		// Similar to IPv4.
		ipv6 := header.IPv6(pkt.NetworkHeader().Slice())
		prot := ipv6.TransportProtocol()
		return extractTransportHeaderPorts(transportHdr, prot)

	default:
		// Unsupported network protocol; cannot extract ports.
		return 0, 0, false
	}
}

// exactPortMatch return true if "srcPort" or "dstPort" are the
// same as "matchPort" depending on the matching criteria specified
// in "flags".
func exactPortMatch(flags uint8, srcPort, dstPort, matchPort uint16) bool {
	switch flags {
	case linux.XT_MULTIPORT_SOURCE:
		return srcPort == matchPort
	case linux.XT_MULTIPORT_DESTINATION:
		return dstPort == matchPort
	case linux.XT_MULTIPORT_EITHER:
		return (srcPort == matchPort) || (dstPort == matchPort)
	}
	return false
}
