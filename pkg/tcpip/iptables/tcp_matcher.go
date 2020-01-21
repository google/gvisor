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

type TCPMatcher struct {
	data TCPMatcherData

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

type TCPMatcherData struct {
	// Filter IPHeaderFilter

	SourcePortStart      uint16
	SourcePortEnd        uint16
	DestinationPortStart uint16
	DestinationPortEnd   uint16
	Option               uint8
	FlagMask             uint8
	FlagCompare          uint8
	InverseFlags         uint8
}

func NewTCPMatcher(filter IPHeaderFilter, data TCPMatcherData) (Matcher, error) {
	// TODO: We currently only support source port and destination port.
	log.Infof("Adding rule with TCPMatcherData: %+v", data)

	if data.Option != 0 ||
		data.FlagMask != 0 ||
		data.FlagCompare != 0 ||
		data.InverseFlags != 0 {
		return nil, fmt.Errorf("unsupported TCP matcher flags set")
	}

	if filter.Protocol != header.TCPProtocolNumber {
		log.Warningf("TCP matching is only valid for protocol %d.", header.TCPProtocolNumber)
	}

	return &TCPMatcher{data: data}, nil
}

// TODO: Check xt_tcpudp.c. Need to check for same things (e.g. fragments).
func (tm *TCPMatcher) Match(hook Hook, pkt tcpip.PacketBuffer, interfaceName string) (bool, bool) {
	netHeader := header.IPv4(pkt.NetworkHeader)

	// TODO: Do we check proto here or elsewhere? I think elsewhere (check
	// codesearch).
	if netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return false, false
	}

	// We dont't match fragments.
	if frag := netHeader.FragmentOffset(); frag != 0 {
		if frag == 1 {
			log.Warningf("Dropping TCP packet: malicious packet with fragment with fragment offest of 1.")
			return false, true
		}
		return false, false
	}

	// Now we need the transport header. However, this may not have been set
	// yet.
	// TODO
	var tcpHeader header.TCP
	if pkt.TransportHeader != nil {
		tcpHeader = header.TCP(pkt.TransportHeader)
	} else {
		// The TCP header hasn't been parsed yet. We have to do it here.
		if len(pkt.Data.First()) < header.TCPMinimumSize {
			// There's no valid TCP header here, so we hotdrop the
			// packet.
			// TODO: Stats.
			log.Warningf("Dropping TCP packet: size to small.")
			return false, true
		}
		tcpHeader = header.TCP(pkt.Data.First())
	}

	// Check whether the source and destination ports are within the
	// matching range.
	sourcePort := tcpHeader.SourcePort()
	destinationPort := tcpHeader.DestinationPort()
	if sourcePort < tm.data.SourcePortStart || tm.data.SourcePortEnd < sourcePort {
		return false, false
	}
	if destinationPort < tm.data.DestinationPortStart || tm.data.DestinationPortEnd < destinationPort {
		return false, false
	}

	return true, false
}
