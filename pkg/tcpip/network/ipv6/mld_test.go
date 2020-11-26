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

package ipv6_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	addr1 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
)

func TestIPv6JoinLeaveSolicitedNodeAddressPerformsMLD(t *testing.T) {
	const nicID = 1

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			MLD: ipv6.MLDOptions{
				Enabled: true,
			},
		})},
	})
	e := channel.New(1, header.IPv6MinimumMTU, "")
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
	}

	// The stack will join an address's solicited node multicast address when
	// an address is added. An MLD report message should be sent for the
	// solicited-node group.
	if err := s.AddAddress(nicID, ipv6.ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ipv6.ProtocolNumber, addr1, err)
	}
	{
		p, ok := e.Read()
		if !ok {
			t.Fatal("expected a report message to be sent")
		}
		snmc := header.SolicitedNodeAddr(addr1)
		checker.IPv6(t, header.IPv6(stack.PayloadSince(p.Pkt.NetworkHeader())),
			checker.DstAddr(snmc),
			// Hop Limit for an MLD message must be 1 as per RFC 2710 section 3.
			checker.TTL(1),
			checker.MLD(header.ICMPv6MulticastListenerReport, header.MLDMinimumSize,
				checker.MLDMaxRespDelay(0),
				checker.MLDMulticastAddress(snmc),
			),
		)
	}

	// The stack will leave an address's solicited node multicast address when
	// an address is removed. An MLD done message should be sent for the
	// solicited-node group.
	if err := s.RemoveAddress(nicID, addr1); err != nil {
		t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr1, err)
	}
	{
		p, ok := e.Read()
		if !ok {
			t.Fatal("expected a done message to be sent")
		}
		snmc := header.SolicitedNodeAddr(addr1)
		checker.IPv6(t, header.IPv6(stack.PayloadSince(p.Pkt.NetworkHeader())),
			checker.DstAddr(header.IPv6AllRoutersMulticastAddress),
			checker.TTL(1),
			checker.MLD(header.ICMPv6MulticastListenerDone, header.MLDMinimumSize,
				checker.MLDMaxRespDelay(0),
				checker.MLDMulticastAddress(snmc),
			),
		)
	}
}
