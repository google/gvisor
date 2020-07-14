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

package ipv6_unknown_options_action_test

import (
	"encoding/binary"
	"flag"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

func mkHopByHopOptionsExtHdr(optType byte) tb.Layer {
	return &tb.IPv6HopByHopOptionsExtHdr{
		Options: []byte{optType, 0x04, 0x00, 0x00, 0x00, 0x00},
	}
}

func mkDestinationOptionsExtHdr(optType byte) tb.Layer {
	return &tb.IPv6DestinationOptionsExtHdr{
		Options: []byte{optType, 0x04, 0x00, 0x00, 0x00, 0x00},
	}
}

func optionTypeFromAction(action header.IPv6OptionUnknownAction) byte {
	return byte(action << 6)
}

func TestIPv6UnknownOptionAction(t *testing.T) {
	for _, tt := range []struct {
		description  string
		mkExtHdr     func(optType byte) tb.Layer
		action       header.IPv6OptionUnknownAction
		multicastDst bool
		wantICMPv6   bool
	}{
		{
			description:  "0b00/hbh",
			mkExtHdr:     mkHopByHopOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionSkip,
			multicastDst: false,
			wantICMPv6:   false,
		},
		{
			description:  "0b01/hbh",
			mkExtHdr:     mkHopByHopOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscard,
			multicastDst: false,
			wantICMPv6:   false,
		},
		{
			description:  "0b10/hbh/unicast",
			mkExtHdr:     mkHopByHopOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMP,
			multicastDst: false,
			wantICMPv6:   true,
		},
		{
			description:  "0b10/hbh/multicast",
			mkExtHdr:     mkHopByHopOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMP,
			multicastDst: true,
			wantICMPv6:   true,
		},
		{
			description:  "0b11/hbh/unicast",
			mkExtHdr:     mkHopByHopOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest,
			multicastDst: false,
			wantICMPv6:   true,
		},
		{
			description:  "0b11/hbh/multicast",
			mkExtHdr:     mkHopByHopOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest,
			multicastDst: true,
			wantICMPv6:   false,
		},
		{
			description:  "0b00/destination",
			mkExtHdr:     mkDestinationOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionSkip,
			multicastDst: false,
			wantICMPv6:   false,
		},
		{
			description:  "0b01/destination",
			mkExtHdr:     mkDestinationOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscard,
			multicastDst: false,
			wantICMPv6:   false,
		},
		{
			description:  "0b10/destination/unicast",
			mkExtHdr:     mkDestinationOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMP,
			multicastDst: false,
			wantICMPv6:   true,
		},
		{
			description:  "0b10/destination/multicast",
			mkExtHdr:     mkDestinationOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMP,
			multicastDst: true,
			wantICMPv6:   true,
		},
		{
			description:  "0b11/destination/unicast",
			mkExtHdr:     mkDestinationOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest,
			multicastDst: false,
			wantICMPv6:   true,
		},
		{
			description:  "0b11/destination/multicast",
			mkExtHdr:     mkDestinationOptionsExtHdr,
			action:       header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest,
			multicastDst: true,
			wantICMPv6:   false,
		},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := tb.NewDUT(t)
			defer dut.TearDown()
			ipv6Conn := tb.NewIPv6Conn(t, tb.IPv6{}, tb.IPv6{})
			conn := (*tb.Connection)(&ipv6Conn)
			defer ipv6Conn.Close()

			outgoingOverride := tb.Layers{}
			if tt.multicastDst {
				outgoingOverride = tb.Layers{&tb.IPv6{
					DstAddr: tb.Address(tcpip.Address(net.ParseIP("ff02::1"))),
				}}
			}

			outgoing := conn.CreateFrame(outgoingOverride, tt.mkExtHdr(optionTypeFromAction(tt.action)))
			conn.SendFrame(outgoing)
			ipv6Sent := outgoing[1:]
			invokingPacket, err := ipv6Sent.ToBytes()
			if err != nil {
				t.Fatalf("failed to serialize the outgoing packet: %s", err)
			}
			icmpv6Payload := make([]byte, 4)
			// The pointer in the ICMPv6 parameter problem message should point to
			// the option type of the unknown option. In our test case, it is the
			// first option in the extension header whose option type is 2 bytes
			// after the IPv6 header (after NextHeader and ExtHdrLen).
			binary.BigEndian.PutUint32(icmpv6Payload, header.IPv6MinimumSize+2)
			icmpv6Payload = append(icmpv6Payload, invokingPacket...)
			gotICMPv6, err := ipv6Conn.ExpectFrame(tb.Layers{
				&tb.Ether{},
				&tb.IPv6{},
				&tb.ICMPv6{
					Type:    tb.ICMPv6Type(header.ICMPv6ParamProblem),
					Code:    tb.Byte(2),
					Payload: icmpv6Payload,
				},
			}, time.Second)
			if tt.wantICMPv6 && err != nil {
				t.Fatalf("expected ICMPv6 Parameter Problem but got none: %s", err)
			}
			if !tt.wantICMPv6 && gotICMPv6 != nil {
				t.Fatalf("expected no ICMPv6 Parameter Problem but got one: %s", gotICMPv6)
			}
		})
	}
}
