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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

type fragmentInfo struct {
	offset uint16
	size   uint16
	more   bool
	id     uint32
}

func TestIPv6FragmentReassembly(t *testing.T) {
	icmpv6ProtoNum := header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber)

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
				{offset: 0, size: 1000, id: 100, more: true},
				{offset: 1000, size: 1000, id: 100, more: true},
				{offset: 2000, size: 1000, id: 100, more: false},
			},
			expectReply: true,
		},
		{
			description:  "out of order fragments",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 101, more: true},
				{offset: 2000, size: 1000, id: 101, more: false},
				{offset: 1000, size: 1000, id: 101, more: true},
			},
			expectReply: true,
		},
		{
			description:  "duplicated fragments",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 102, more: true},
				{offset: 1000, size: 1000, id: 102, more: true},
				{offset: 1000, size: 1000, id: 102, more: true},
				{offset: 2000, size: 1000, id: 102, more: false},
			},
			expectReply: true,
		},
		{
			description:  "fragment subset",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 103, more: true},
				{offset: 1000, size: 1000, id: 103, more: true},
				{offset: 512, size: 256, id: 103, more: true},
				{offset: 2000, size: 1000, id: 103, more: false},
			},
			expectReply: true,
		},
		{
			description:  "fragment overlap",
			ipPayloadLen: 3000,
			fragments: []fragmentInfo{
				{offset: 0, size: 1000, id: 104, more: true},
				{offset: 1512, size: 1000, id: 104, more: true},
				{offset: 1000, size: 1000, id: 104, more: true},
				{offset: 2000, size: 1000, id: 104, more: false},
			},
			expectReply: false,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			lIP := tcpip.Address(dut.Net.LocalIPv6)
			rIP := tcpip.Address(dut.Net.RemoteIPv6)

			data := make([]byte, test.ipPayloadLen)
			icmp := header.ICMPv6(data[:header.ICMPv6HeaderSize])
			icmp.SetType(header.ICMPv6EchoRequest)
			icmp.SetCode(header.ICMPv6UnusedCode)
			icmp.SetChecksum(0)
			originalPayload := data[header.ICMPv6HeaderSize:]
			if _, err := rand.Read(originalPayload); err != nil {
				t.Fatalf("rand.Read: %s", err)
			}

			cksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header:      icmp,
				Src:         lIP,
				Dst:         rIP,
				PayloadCsum: header.Checksum(originalPayload, 0 /* initial */),
				PayloadLen:  len(originalPayload),
			})
			icmp.SetChecksum(cksum)

			for _, fragment := range test.fragments {
				conn.Send(t, testbench.IPv6{},
					&testbench.IPv6FragmentExtHdr{
						NextHeader:     &icmpv6ProtoNum,
						FragmentOffset: testbench.Uint16(fragment.offset / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit),
						MoreFragments:  testbench.Bool(fragment.more),
						Identification: testbench.Uint32(fragment.id),
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
					if test.expectReply && bytesReceived < test.ipPayloadLen {
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
