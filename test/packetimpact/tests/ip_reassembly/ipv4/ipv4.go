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

// Package ipv4 contains the code to run an IP reassembly test.
package ipv4

import (
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
	"gvisor.dev/gvisor/test/packetimpact/tests/ip_reassembly/common"
)

// Run executes an IP reassembly test.
func Run(t *testing.T, test common.TestCase) {
	icmpv4ProtoNum := uint8(header.ICMPv4ProtocolNumber)

	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	conn := testbench.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
	defer conn.Close(t)

	data := make([]byte, test.IPPayloadLen)
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

	for _, fragment := range test.Fragments {
		var more uint8
		if fragment.More {
			more = header.IPv4FlagMoreFragments
		}
		conn.Send(t,
			testbench.IPv4{
				Protocol:       &icmpv4ProtoNum,
				FragmentOffset: testbench.Uint16(fragment.Offset),
				Flags:          testbench.Uint8(more),
				ID:             testbench.Uint16(fragment.ID),
			},
			&testbench.Payload{
				Bytes: data[fragment.Offset:][:fragment.Size],
			})
	}

	var bytesReceived int
	reassembledPayload := make([]byte, test.IPPayloadLen)
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
			if test.ExpectReply && bytesReceived < test.IPPayloadLen {
				t.Fatalf("received %d bytes out of %d, then conn.ExpectFrame(_, _, time.Second) failed with %s", bytesReceived, test.IPPayloadLen, err)
			}
			break
		}
		if !test.ExpectReply {
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

	if test.ExpectReply {
		if diff := cmp.Diff(originalPayload, reassembledPayload[header.ICMPv4MinimumSize:]); diff != "" {
			t.Fatalf("reassembledPayload mismatch (-want +got):\n%s", diff)
		}
	}
}
