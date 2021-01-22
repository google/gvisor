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

const matcherNameTCP = "tcp"

func init() {
	registerMatchMaker(tcpMarshaler{})
}

// tcpMarshaler implements matchMaker for TCP matching.
type tcpMarshaler struct{}

// name implements matchMaker.name.
func (tcpMarshaler) name() string {
	return matcherNameTCP
}

// marshal implements matchMaker.marshal.
func (tcpMarshaler) marshal(mr stack.Matcher) []byte {
	matcher := mr.(*TCPMatcher)
	xttcp := linux.XTTCP{
		SourcePortStart:      matcher.sourcePortStart,
		SourcePortEnd:        matcher.sourcePortEnd,
		DestinationPortStart: matcher.destinationPortStart,
		DestinationPortEnd:   matcher.destinationPortEnd,
	}
	buf := make([]byte, 0, linux.SizeOfXTTCP)
	return marshalEntryMatch(matcherNameTCP, binary.Marshal(buf, usermem.ByteOrder, xttcp))
}

// unmarshal implements matchMaker.unmarshal.
func (tcpMarshaler) unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfXTTCP {
		return nil, fmt.Errorf("buf has insufficient size for TCP match: %d", len(buf))
	}

	// For alignment reasons, the match's total size may
	// exceed what's strictly necessary to hold matchData.
	var matchData linux.XTTCP
	binary.Unmarshal(buf[:linux.SizeOfXTTCP], usermem.ByteOrder, &matchData)
	nflog("parseMatchers: parsed XTTCP: %+v", matchData)

	if matchData.Option != 0 ||
		matchData.FlagMask != 0 ||
		matchData.FlagCompare != 0 ||
		matchData.InverseFlags != 0 {
		return nil, fmt.Errorf("unsupported TCP matcher flags set")
	}

	if filter.Protocol != header.TCPProtocolNumber {
		return nil, fmt.Errorf("TCP matching is only valid for protocol %d", header.TCPProtocolNumber)
	}

	return &TCPMatcher{
		sourcePortStart:      matchData.SourcePortStart,
		sourcePortEnd:        matchData.SourcePortEnd,
		destinationPortStart: matchData.DestinationPortStart,
		destinationPortEnd:   matchData.DestinationPortEnd,
	}, nil
}

// TCPMatcher matches TCP packets and their headers. It implements Matcher.
type TCPMatcher struct {
	sourcePortStart      uint16
	sourcePortEnd        uint16
	destinationPortStart uint16
	destinationPortEnd   uint16
}

// Name implements Matcher.Name.
func (*TCPMatcher) Name() string {
	return matcherNameTCP
}

// Match implements Matcher.Match.
func (tm *TCPMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	// TODO(gvisor.dev/issue/170): Proto checks should ultimately be moved
	// into the stack.Check codepath as matchers are added.
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		netHeader := header.IPv4(pkt.NetworkHeader().View())
		if netHeader.TransportProtocol() != header.TCPProtocolNumber {
			return false, false
		}

		// We don't match fragments.
		if frag := netHeader.FragmentOffset(); frag != 0 {
			if frag == 1 {
				return false, true
			}
			return false, false
		}

	case header.IPv6ProtocolNumber:
		// As in Linux, we do not perform an IPv6 fragment check. See
		// xt_action_param.fragoff in
		// include/linux/netfilter/x_tables.h.
		if header.IPv6(pkt.NetworkHeader().View()).TransportProtocol() != header.TCPProtocolNumber {
			return false, false
		}

	default:
		// We don't know the network protocol.
		return false, false
	}

	tcpHeader := header.TCP(pkt.TransportHeader().View())
	if len(tcpHeader) < header.TCPMinimumSize {
		// There's no valid TCP header here, so we drop the packet immediately.
		return false, true
	}

	// Check whether the source and destination ports are within the
	// matching range.
	if sourcePort := tcpHeader.SourcePort(); sourcePort < tm.sourcePortStart || tm.sourcePortEnd < sourcePort {
		return false, false
	}
	if destinationPort := tcpHeader.DestinationPort(); destinationPort < tm.destinationPortStart || tm.destinationPortEnd < destinationPort {
		return false, false
	}

	return true, false
}
