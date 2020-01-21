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
	"runtime/debug"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type UDPMatcher struct {
	data UDPMatcherData

	// tablename string
	// unsigned int matchsize;
	// unsigned int usersize;
	// #ifdef CONFIG_COMPAT
	// unsigned int compatsize;
	// #endif
	// unsigned int hooks;
	// unsigned short proto;
	// unsigned short family;
}

// TODO: Delete?
// MatchCheckEntryParams

type UDPMatcherData struct {
	// Filter IPHeaderFilter

	SourcePortStart      uint16
	SourcePortEnd        uint16
	DestinationPortStart uint16
	DestinationPortEnd   uint16
	InverseFlags         uint8
}

func NewUDPMatcher(filter IPHeaderFilter, data UDPMatcherData) (Matcher, error) {
	// TODO: We currently only support source port and destination port.
	log.Infof("Adding rule with UDPMatcherData: %+v", data)

	if data.InverseFlags != 0 {
		return nil, fmt.Errorf("unsupported UDP matcher flags set")
	}

	if filter.Protocol != header.UDPProtocolNumber {
		log.Warningf("UDP matching is only valid for protocol %d.", header.UDPProtocolNumber)
	}

	return &UDPMatcher{data: data}, nil
}

// TODO: Check xt_tcpudp.c. Need to check for same things (e.g. fragments).
func (tm *UDPMatcher) Match(hook Hook, pkt tcpip.PacketBuffer, interfaceName string) (bool, bool) {
	log.Infof("UDPMatcher called from: %s", string(debug.Stack()))
	netHeader := header.IPv4(pkt.NetworkHeader)

	// TODO: Do we check proto here or elsewhere? I think elsewhere (check
	// codesearch).
	if netHeader.TransportProtocol() != header.UDPProtocolNumber {
		log.Infof("UDPMatcher: wrong protocol number")
		return false, false
	}

	// We dont't match fragments.
	if frag := netHeader.FragmentOffset(); frag != 0 {
		log.Infof("UDPMatcher: it's a fragment")
		if frag == 1 {
			return false, true
		}
		log.Warningf("Dropping UDP packet: malicious fragmented packet.")
		return false, false
	}

	// Now we need the transport header. However, this may not have been set
	// yet.
	// TODO
	var udpHeader header.UDP
	if pkt.TransportHeader != nil {
		log.Infof("UDPMatcher: transport header is not nil")
		udpHeader = header.UDP(pkt.TransportHeader)
	} else {
		log.Infof("UDPMatcher: transport header is nil")
		log.Infof("UDPMatcher: is network header nil: %t", pkt.NetworkHeader == nil)
		// The UDP header hasn't been parsed yet. We have to do it here.
		if len(pkt.Data.First()) < header.UDPMinimumSize {
			// There's no valid UDP header here, so we hotdrop the
			// packet.
			// TODO: Stats.
			log.Warningf("Dropping UDP packet: size to small.")
			return false, true
		}
		udpHeader = header.UDP(pkt.Data.First())
	}

	// Check whether the source and destination ports are within the
	// matching range.
	sourcePort := udpHeader.SourcePort()
	destinationPort := udpHeader.DestinationPort()
	log.Infof("UDPMatcher: sport and dport are %d and %d. sports and dport start and end are (%d, %d) and (%d, %d)",
		udpHeader.SourcePort(), udpHeader.DestinationPort(),
		tm.data.SourcePortStart, tm.data.SourcePortEnd,
		tm.data.DestinationPortStart, tm.data.DestinationPortEnd)
	if sourcePort < tm.data.SourcePortStart || tm.data.SourcePortEnd < sourcePort {
		return false, false
	}
	if destinationPort < tm.data.DestinationPortStart || tm.data.DestinationPortEnd < destinationPort {
		return false, false
	}

	return true, false
}
