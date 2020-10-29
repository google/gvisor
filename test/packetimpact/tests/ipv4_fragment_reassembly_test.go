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
	testbench.RegisterFlags(flag.CommandLine)
}

type fragmentInfo struct {
	offset uint16
	size   uint16
	more   uint8
}

func TestIPv4FragmentReassembly(t *testing.T) {
	const fragmentID = 42
	icmpv4ProtoNum := uint8(header.ICMPv4ProtocolNumber)

	tests := []struct {
		description  string
		ipPayloadLen int
		fragments    []fragmentInfo
		expectReply  bool
	}{
		{
			description:  "basic reassembly",
			ipPayloadLen: 2000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, more: header.IPv4FlagMoreFragments},
				{offset: 1000, size: 1000, more: 0},
			},
			expectReply: true,
		},
		{
			description:  "out of order fragments",
			ipPayloadLen: 2000,
			fragments: []fragmentInfo{
				{offset: 1000, size: 1000, more: 0},
				{offset: 0, size: 1000, more: header.IPv4FlagMoreFragments},
			},
			expectReply: true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			conn := testbench.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
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
						ID:             testbench.Uint16(fragmentID),
					},
					&testbench.Payload{
						Bytes: data[fragment.offset:][:fragment.size],
					})
			}

			var bytesReceived int
			reassembledPayload := make([]byte, test.ipPayloadLen)
			for {
				incomingFrame, err := conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv4{},
					&testbench.ICMPv4{},
				}, time.Second)
				if err != nil {
					// Either an unexpected frame was received, or none at all.
					if bytesReceived < test.ipPayloadLen {
						t.Fatalf("received %d bytes out of %d, then conn.ExpectFrame(_, _, time.Second) failed with %s", bytesReceived, test.ipPayloadLen, err)
					}
					break
				}
				if !test.expectReply {
					t.Fatalf("unexpected reply received:\n%s", incomingFrame)
				}
				ipPayload, err := incomingFrame[2 /* ICMPv4 */].ToBytes()
				if err != nil {
					t.Fatalf("failed to parse ICMPv4 header: incomingPacket[2].ToBytes() = (_, %s)", err)
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
