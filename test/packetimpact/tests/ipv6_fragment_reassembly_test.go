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

package ipv6_fragment_reassembly_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	// The payload length for the first fragment we send. This number
	// is a multiple of 8 near 750 (half of 1500).
	firstPayloadLength = 752
	// The ID field for our outgoing fragments.
	fragmentID = 1
	// A node must be able to accept a fragmented packet that,
	// after reassembly, is as large as 1500 octets.
	reassemblyCap = 1500
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestIPv6FragmentReassembly(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	conn := testbench.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
	defer conn.Close()

	firstPayloadToSend := make([]byte, firstPayloadLength)
	for i := range firstPayloadToSend {
		firstPayloadToSend[i] = 'A'
	}

	secondPayloadLength := reassemblyCap - firstPayloadLength - header.ICMPv6EchoMinimumSize
	secondPayloadToSend := firstPayloadToSend[:secondPayloadLength]

	icmpv6EchoPayload := make([]byte, 4)
	binary.BigEndian.PutUint16(icmpv6EchoPayload[0:], 0)
	binary.BigEndian.PutUint16(icmpv6EchoPayload[2:], 0)
	icmpv6EchoPayload = append(icmpv6EchoPayload, firstPayloadToSend...)

	lIP := tcpip.Address(net.ParseIP(testbench.LocalIPv6).To16())
	rIP := tcpip.Address(net.ParseIP(testbench.RemoteIPv6).To16())
	icmpv6 := testbench.ICMPv6{
		Type:    testbench.ICMPv6Type(header.ICMPv6EchoRequest),
		Code:    testbench.Byte(0),
		Payload: icmpv6EchoPayload,
	}
	icmpv6Bytes, err := icmpv6.ToBytes()
	if err != nil {
		t.Fatalf("failed to serialize ICMPv6: %s", err)
	}
	cksum := header.ICMPv6Checksum(
		header.ICMPv6(icmpv6Bytes),
		lIP,
		rIP,
		buffer.NewVectorisedView(len(secondPayloadToSend), []buffer.View{secondPayloadToSend}),
	)

	conn.Send(testbench.IPv6{},
		&testbench.IPv6FragmentExtHdr{
			FragmentOffset: testbench.Uint16(0),
			MoreFragments:  testbench.Bool(true),
			Identification: testbench.Uint32(fragmentID),
		},
		&testbench.ICMPv6{
			Type:     testbench.ICMPv6Type(header.ICMPv6EchoRequest),
			Code:     testbench.Byte(0),
			Payload:  icmpv6EchoPayload,
			Checksum: &cksum,
		})

	icmpv6ProtoNum := header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber)

	conn.Send(testbench.IPv6{},
		&testbench.IPv6FragmentExtHdr{
			NextHeader:     &icmpv6ProtoNum,
			FragmentOffset: testbench.Uint16((firstPayloadLength + header.ICMPv6EchoMinimumSize) / 8),
			MoreFragments:  testbench.Bool(false),
			Identification: testbench.Uint32(fragmentID),
		},
		&testbench.Payload{
			Bytes: secondPayloadToSend,
		})

	gotEchoReplyFirstPart, err := conn.ExpectFrame(testbench.Layers{
		&testbench.Ether{},
		&testbench.IPv6{},
		&testbench.IPv6FragmentExtHdr{
			FragmentOffset: testbench.Uint16(0),
			MoreFragments:  testbench.Bool(true),
		},
		&testbench.ICMPv6{
			Type: testbench.ICMPv6Type(header.ICMPv6EchoReply),
			Code: testbench.Byte(0),
		},
	}, time.Second)
	if err != nil {
		t.Fatalf("expected a fragmented ICMPv6 Echo Reply, but got none: %s", err)
	}

	id := *gotEchoReplyFirstPart[2].(*testbench.IPv6FragmentExtHdr).Identification
	gotFirstPayload, err := gotEchoReplyFirstPart[len(gotEchoReplyFirstPart)-1].ToBytes()
	if err != nil {
		t.Fatalf("failed to serialize ICMPv6: %s", err)
	}
	icmpPayload := gotFirstPayload[header.ICMPv6EchoMinimumSize:]
	receivedLen := len(icmpPayload)
	wantSecondPayloadLen := reassemblyCap - header.ICMPv6EchoMinimumSize - receivedLen
	wantFirstPayload := make([]byte, receivedLen)
	for i := range wantFirstPayload {
		wantFirstPayload[i] = 'A'
	}
	wantSecondPayload := wantFirstPayload[:wantSecondPayloadLen]
	if !bytes.Equal(icmpPayload, wantFirstPayload) {
		t.Fatalf("received unexpected payload, got: %s, want: %s",
			hex.Dump(icmpPayload),
			hex.Dump(wantFirstPayload))
	}

	gotEchoReplySecondPart, err := conn.ExpectFrame(testbench.Layers{
		&testbench.Ether{},
		&testbench.IPv6{},
		&testbench.IPv6FragmentExtHdr{
			NextHeader:     &icmpv6ProtoNum,
			FragmentOffset: testbench.Uint16(uint16((receivedLen + header.ICMPv6EchoMinimumSize) / 8)),
			MoreFragments:  testbench.Bool(false),
			Identification: &id,
		},
		&testbench.ICMPv6{},
	}, time.Second)
	if err != nil {
		t.Fatalf("expected the rest of ICMPv6 Echo Reply, but got none: %s", err)
	}
	secondPayload, err := gotEchoReplySecondPart[len(gotEchoReplySecondPart)-1].ToBytes()
	if err != nil {
		t.Fatalf("failed to serialize ICMPv6 Echo Reply: %s", err)
	}
	if !bytes.Equal(secondPayload, wantSecondPayload) {
		t.Fatalf("received unexpected payload, got: %s, want: %s",
			hex.Dump(secondPayload),
			hex.Dump(wantSecondPayload))
	}
}
