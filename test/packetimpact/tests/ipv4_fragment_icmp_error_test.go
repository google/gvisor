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

package ipv4_fragment_icmp_error_test

import (
	"flag"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	data              = "IPV4_PROTOCOL_TESTER_FOR_FRAGMENT"
	fragmentID        = 1
	reassemblyTimeout = ipv4.ReassembleTimeout + 5*time.Second
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func fragmentedICMPEchoRequest(t *testing.T, n *testbench.DUTTestNet, conn *testbench.IPv4Conn, firstPayloadLength uint16, payload []byte, secondFragmentOffset uint16) ([]testbench.Layers, [][]byte) {
	t.Helper()

	icmp := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize))
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetCode(header.ICMPv4UnusedCode)
	icmp.SetChecksum(0)
	icmp.SetSequence(0)
	icmp.SetIdent(0)
	cksum := header.ICMPv4Checksum(icmp, header.Checksum(payload, 0 /* initial */))
	icmp.SetChecksum(cksum)
	icmpv4Bytes := append([]byte(icmp), payload...)

	firstFragment := conn.CreateFrame(t,
		testbench.Layers{
			&testbench.IPv4{
				ID:             testbench.Uint16(fragmentID),
				Flags:          testbench.Uint8(header.IPv4FlagMoreFragments),
				FragmentOffset: testbench.Uint16(0),
				Protocol:       testbench.Uint8(uint8(header.ICMPv4ProtocolNumber)),
			},
		},
		&testbench.Payload{
			Bytes: icmpv4Bytes[:header.ICMPv4PayloadOffset+firstPayloadLength],
		},
	)
	firstIPv4 := firstFragment[1:]
	firstIPv4Bytes, err := firstIPv4.ToBytes()
	if err != nil {
		t.Fatalf("can't convert first %s to bytes: %s", firstIPv4, err)
	}

	secondFragment := conn.CreateFrame(t,
		testbench.Layers{
			&testbench.IPv4{
				ID:             testbench.Uint16(fragmentID),
				Flags:          testbench.Uint8(0),
				FragmentOffset: testbench.Uint16(secondFragmentOffset),
				Protocol:       testbench.Uint8(uint8(header.ICMPv4ProtocolNumber)),
			},
		},
		&testbench.Payload{
			Bytes: icmpv4Bytes[header.ICMPv4PayloadOffset+firstPayloadLength:],
		},
	)
	secondIPv4 := secondFragment[1:]
	secondIPv4Bytes, err := secondIPv4.ToBytes()
	if err != nil {
		t.Fatalf("can't convert %s to bytes: %s", secondIPv4, err)
	}

	return []testbench.Layers{firstFragment, secondFragment}, [][]byte{firstIPv4Bytes, secondIPv4Bytes}
}

func TestIPv4FragmentReassemblyTimeout(t *testing.T) {
	tests := []struct {
		name                  string
		firstPayloadLength    uint16
		payload               []byte
		secondFragmentOffset  uint16
		sendFrameOrder        []int
		expectICMP            bool
		expectType            header.ICMPv4Type
		expectCode            header.ICMPv4Code
		expectPayloadFragment int
	}{
		{
			name:                  "reassemble two fragments",
			firstPayloadLength:    8,
			payload:               []byte(data)[:20],
			secondFragmentOffset:  header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:        []int{1, 2},
			expectICMP:            true,
			expectType:            header.ICMPv4EchoReply,
			expectCode:            header.ICMPv4UnusedCode,
			expectPayloadFragment: 0, /* not a fragment */
		},
		{
			name:                  "reassemble two fragments in reverse order",
			firstPayloadLength:    8,
			payload:               []byte(data)[:20],
			secondFragmentOffset:  header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:        []int{2, 1},
			expectICMP:            true,
			expectType:            header.ICMPv4EchoReply,
			expectCode:            header.ICMPv4UnusedCode,
			expectPayloadFragment: 0, /* not a fragment */
		},
		{
			name:                  "reassembly timeout (first fragment only)",
			firstPayloadLength:    8,
			payload:               []byte(data)[:20],
			secondFragmentOffset:  header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:        []int{1},
			expectICMP:            true,
			expectType:            header.ICMPv4TimeExceeded,
			expectCode:            header.ICMPv4ReassemblyTimeout,
			expectPayloadFragment: 1,
		},
		{
			name:                 "reassembly timeout (second fragment only)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:       []int{2},
			expectICMP:           false,
		},
		{
			name:                  "reassembly timeout (two fragments with a hole)",
			firstPayloadLength:    8,
			payload:               []byte(data)[:20],
			secondFragmentOffset:  header.ICMPv4PayloadOffset + 16,
			sendFrameOrder:        []int{1, 2},
			expectICMP:            true,
			expectType:            header.ICMPv4TimeExceeded,
			expectCode:            header.ICMPv4ReassemblyTimeout,
			expectPayloadFragment: 1,
		},
		{
			name:                  "reassembly timeout (two fragments with a hole in reverse order)",
			firstPayloadLength:    8,
			payload:               []byte(data)[:20],
			secondFragmentOffset:  header.ICMPv4PayloadOffset + 16,
			sendFrameOrder:        []int{2, 1},
			expectICMP:            true,
			expectType:            header.ICMPv4TimeExceeded,
			expectCode:            header.ICMPv4ReassemblyTimeout,
			expectPayloadFragment: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			defer conn.Close(t)

			fragments, ipv4Bytes := fragmentedICMPEchoRequest(t, dut.Net, &conn, test.firstPayloadLength, test.payload, test.secondFragmentOffset)

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			incomingFrames, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv4{},
				&testbench.ICMPv4{},
			}, reassemblyTimeout)
			if err != nil {
				if test.expectICMP {
					t.Fatalf("didn't receive an ICMPv4 Message: %s", err)
				}
				return
			}
			icmpV4 := incomingFrames[2 /* ICMPv4 */].(*testbench.ICMPv4)
			if *icmpV4.Type != test.expectType {
				t.Errorf("got icmpV4.Type=%d want=%d", *icmpV4.Type, test.expectType)
			}
			if *icmpV4.Code != test.expectCode {
				t.Errorf("got icmpV4.Code=%d want=%d", *icmpV4.Code, test.expectCode)
			}
			gotPayload, err := icmpV4.ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv4 to bytes: %s", err)
			}
			icmpPayload := gotPayload[header.ICMPv4PayloadOffset:]
			var wantPayload []byte
			switch test.expectPayloadFragment {
			case 0: /* not a fragment */
				wantPayload = test.payload
			default:
				wantPayload = ipv4Bytes[test.expectPayloadFragment-1]
			}
			if diff := cmp.Diff(wantPayload, icmpPayload); diff != "" {
				t.Fatalf("payload mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
