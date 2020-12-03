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

package ipv4_fragment_reassembly_test

import (
	"flag"
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

type fragmentInfo struct {
	offset uint16
	size   uint16
	more   uint8
	id     uint16
}

func TestIPv4FragmentReassembly(t *testing.T) {
	icmpv4ProtoNum := uint8(header.ICMPv4ProtocolNumber)

	tests := []struct {
		description  string
		ipPayloadLen int
		fragments    []fragmentInfo
		expectReply  bool
	}{
		{
			description:  "basic reassembly",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 5, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, id: 5, more: header.IPv4FlagMoreFragments},
				{offset: 2000, size: 1000, id: 5, more: 0},
			},
			expectReply: true,
		},
		{
			description:  "out of order fragments",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 2000, size: 1000, id: 6, more: 0},
				{offset: 0, size: 1000, id: 6, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, id: 6, more: header.IPv4FlagMoreFragments},
			},
			expectReply: true,
		},
		{
			description:  "duplicated fragments",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 7, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, id: 7, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, id: 7, more: header.IPv4FlagMoreFragments},
				{offset: 2000, size: 1000, id: 7, more: 0},
			},
			expectReply: true,
		},
		{
			description:  "fragment subset",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 8, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, id: 8, more: header.IPv4FlagMoreFragments},
				{offset: 512, size: 256, id: 8, more: header.IPv4FlagMoreFragments},
				{offset: 2000, size: 1000, id: 8, more: 0},
			},
			expectReply: true,
		},
		{
			description:  "fragment overlap",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 9, more: header.IPv4FlagMoreFragments},
				{offset: 1512, size: 1000, id: 9, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, id: 9, more: header.IPv4FlagMoreFragments},
				{offset: 2000, size: 1000, id: 9, more: 0},
			},
			expectReply: false,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			defer conn.Close(t)

			data := make([]byte, test.ipPayloadLen)
			icmp := header.ICMPv4(data[:header.ICMPv4MinimumSize])
			icmp.SetType(header.ICMPv4Echo)
			icmp.SetCode(header.ICMPv4UnusedCode)
			icmp.SetChecksum(0)
			icmp.SetSequence(0)
			icmp.SetIdent(0)
			originalPayload := data[header.ICMPv4MinimumSize:]
			if _, err := rand.Read(originalPayload); err != nil {
				t.Fatalf("rand.Read: %s", err)
			}
			cksum := header.ICMPv4Checksum(
				icmp,
				buffer.NewVectorisedView(len(originalPayload), []buffer.View{originalPayload}),
			)
			icmp.SetChecksum(cksum)

			for _, fragment := range test.fragments {
				conn.Send(t,
					testbench.IPv4{
						Protocol:       &icmpv4ProtoNum,
						FragmentOffset: testbench.Uint16(fragment.offset),
						Flags:          testbench.Uint8(fragment.more),
						ID:             testbench.Uint16(fragment.id),
					},
					&testbench.Payload{
						Bytes: data[fragment.offset:][:fragment.size],
					})
			}

			var bytesReceived int
			reassembledPayload := make([]byte, test.ipPayloadLen)
			// We are sending a packet fragmented into smaller parts but the
			// response may also be large enough to require fragmentation.
			// Therefore we only look for payload for an IPv4 packet not ICMP.
			for {
				incomingFrame, err := conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv4{},
				}, time.Second)
				if err != nil {
					// Either an unexpected frame was received, or none at all.
					if test.expectReply && bytesReceived < test.ipPayloadLen {
						t.Fatalf("received %d bytes out of %d, then conn.ExpectFrame(_, _, time.Second) failed with %s", bytesReceived, test.ipPayloadLen, err)
					}
					break
				}
				if !test.expectReply {
					t.Fatalf("unexpected reply received:\n%s", incomingFrame)
				}
				// We only asked for Ethernet and IPv4 so the rest should be payload.
				ipPayload, err := incomingFrame[2 /* Payload */].ToBytes()
				if err != nil {
					t.Fatalf("failed to parse payload: incomingPacket[2].ToBytes() = (_, %s)", err)
				}
				offset := *incomingFrame[1 /* IPv4 */].(*testbench.IPv4).FragmentOffset
				if copied := copy(reassembledPayload[offset:], ipPayload); copied != len(ipPayload) {
					t.Fatalf("wrong number of bytes copied into reassembledPayload: got = %d, want = %d", copied, len(ipPayload))
				}
				bytesReceived += len(ipPayload)
			}

			if test.expectReply {
				if diff := cmp.Diff(originalPayload, reassembledPayload[header.ICMPv4MinimumSize:]); diff != "" {
					t.Fatalf("reassembledPayload mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
