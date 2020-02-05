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

package iptables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TODO(gvisor.dev/issue/170): The following per-matcher params should be
// supported:
// - Table name
// - Match size
// - User size
// - Hooks
// - Proto
// - Family

// UDPMatcher matches UDP packets and their headers. It implements Matcher.
type UDPMatcher struct {
	Data UDPMatcherParams
}

// UDPMatcherParams are the parameters used to create a UDPMatcher.
type UDPMatcherParams struct {
	SourcePortStart      uint16
	SourcePortEnd        uint16
	DestinationPortStart uint16
	DestinationPortEnd   uint16
	InverseFlags         uint8
}

// NewUDPMatcher returns a new instance of UDPMatcher.
func NewUDPMatcher(filter IPHeaderFilter, data UDPMatcherParams) (Matcher, error) {
	log.Infof("Adding rule with UDPMatcherParams: %+v", data)

	if data.InverseFlags != 0 {
		return nil, fmt.Errorf("unsupported UDP matcher inverse flags set")
	}

	if filter.Protocol != header.UDPProtocolNumber {
		return nil, fmt.Errorf("UDP matching is only valid for protocol %d", header.UDPProtocolNumber)
	}

	return &UDPMatcher{Data: data}, nil
}

// Match implements Matcher.Match.
func (um *UDPMatcher) Match(hook Hook, pkt tcpip.PacketBuffer, interfaceName string) (bool, bool) {
	netHeader := header.IPv4(pkt.NetworkHeader)

	// TODO(gvisor.dev/issue/170): Proto checks should ultimately be moved
	// into the iptables.Check codepath as matchers are added.
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
	// ultimately be moved into the iptables.Check codepath as matchers are
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
	if sourcePort := udpHeader.SourcePort(); sourcePort < um.Data.SourcePortStart || um.Data.SourcePortEnd < sourcePort {
		return false, false
	}
	if destinationPort := udpHeader.DestinationPort(); destinationPort < um.Data.DestinationPortStart || um.Data.DestinationPortEnd < destinationPort {
		return false, false
	}

	return true, false
}
