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
	"flag"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
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
	more   bool
}

func TestIPv6FragmentReassembly(t *testing.T) {
	const fragmentID = 43
	icmpv6ProtoNum := header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber)

	tests := []struct {
		description  string
		ipPayloadLen int
		fragments    []fragmentInfo
		expectReply  bool
	}{
		{
			description:  "basic reassembly",
			ipPayloadLen: 1500,
			fragments: []fragmentInfo{
				{offset: 0, size: 760, more: true},
				{offset: 760, size: 740, more: false},
			},
			expectReply: true,
		},
		{
			description:  "out of order fragments",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1024, more: true},
				{offset: 2048, size: 952, more: false},
				{offset: 1024, size: 1024, more: true},
			},
			expectReply: true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			conn := testbench.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			lIP := tcpip.Address(net.ParseIP(testbench.LocalIPv6).To16())
			rIP := tcpip.Address(net.ParseIP(testbench.RemoteIPv6).To16())

			data := make([]byte, test.ipPayloadLen)
			icmp := header.ICMPv6(data[:header.ICMPv6HeaderSize])
			icmp.SetType(header.ICMPv6EchoRequest)
			icmp.SetCode(header.ICMPv6UnusedCode)
			icmp.SetChecksum(0)
			originalPayload := data[header.ICMPv6HeaderSize:]
			if _, err := rand.Read(originalPayload); err != nil {
				t.Fatalf("rand.Read: %s", err)
			}

			cksum := header.ICMPv6Checksum(
				icmp,
				lIP,
				rIP,
				buffer.NewVectorisedView(len(originalPayload), []buffer.View{originalPayload}),
			)
			icmp.SetChecksum(cksum)

			for _, fragment := range test.fragments {
				conn.Send(t, testbench.IPv6{},
					&testbench.IPv6FragmentExtHdr{
						NextHeader:     &icmpv6ProtoNum,
						FragmentOffset: testbench.Uint16(fragment.offset / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit),
						MoreFragments:  testbench.Bool(fragment.more),
						Identification: testbench.Uint32(fragmentID),
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
					&testbench.IPv6{},
					&testbench.IPv6FragmentExtHdr{},
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
				ipPayload, err := incomingFrame[3 /* Payload */].ToBytes()
				if err != nil {
					t.Fatalf("failed to parse ICMPv6 header: incomingPacket[3].ToBytes() = (_, %s)", err)
				}
				offset := *incomingFrame[2 /* IPv6FragmentExtHdr */].(*testbench.IPv6FragmentExtHdr).FragmentOffset
				offset *= header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit
				if copied := copy(reassembledPayload[offset:], ipPayload); copied != len(ipPayload) {
					t.Fatalf("wrong number of bytes copied into reassembledPayload: got = %d, want = %d", copied, len(ipPayload))
				}
				bytesReceived += len(ipPayload)
			}

			if test.expectReply {
				if diff := cmp.Diff(originalPayload, reassembledPayload[header.ICMPv6HeaderSize:]); diff != "" {
					t.Fatalf("reassembledPayload mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
