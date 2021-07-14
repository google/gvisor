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
	"bytes"
	"encoding/hex"
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

func TestIPv4ICMPEchoRequestFragmentReassembly(t *testing.T) {
	tests := []struct {
		name                 string
		firstPayloadLength   uint16
		payload              []byte
		secondFragmentOffset uint16
		sendFrameOrder       []int
	}{
		{
			name:                 "reassemble two fragments",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:       []int{1, 2},
		},
		{
			name:                 "reassemble two fragments in reverse order",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:       []int{2, 1},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			defer conn.Close(t)

			fragments, _ := fragmentedICMPEchoRequest(t, dut.Net, &conn, test.firstPayloadLength, test.payload, test.secondFragmentOffset)

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			gotEchoReply, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv4{},
				&testbench.ICMPv4{
					Type: testbench.ICMPv4Type(header.ICMPv4EchoReply),
					Code: testbench.ICMPv4Code(header.ICMPv4UnusedCode),
				},
			}, time.Second)
			if err != nil {
				t.Fatalf("expected an ICMPv4 Echo Reply, but got none: %s", err)
			}
			gotPayload, err := gotEchoReply[len(gotEchoReply)-1].ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv4 to bytes: %s", err)
			}
			icmpPayload := gotPayload[header.ICMPv4PayloadOffset:]
			wantPayload := test.payload
			if !bytes.Equal(icmpPayload, wantPayload) {
				t.Fatalf("received unexpected payload, got: %s, want: %s",
					hex.Dump(icmpPayload),
					hex.Dump(wantPayload))
			}
		})
	}
}

func TestIPv4FragmentReassemblyTimeout(t *testing.T) {
	type icmpFramePattern struct {
		typ  header.ICMPv4Type
		code header.ICMPv4Code
	}

	type icmpReassemblyTimeoutDetail struct {
		payloadFragment int // 1: first fragment, 2: second fragnemt.
	}

	tests := []struct {
		name                        string
		firstPayloadLength          uint16
		payload                     []byte
		secondFragmentOffset        uint16
		sendFrameOrder              []int
		replyFilter                 icmpFramePattern
		expectErrorReply            bool
		expectICMPReassemblyTimeout icmpReassemblyTimeoutDetail
	}{
		{
			name:                 "reassembly timeout (first fragment only)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:       []int{1},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv4TimeExceeded,
				code: header.ICMPv4ReassemblyTimeout,
			},
			expectErrorReply: true,
			expectICMPReassemblyTimeout: icmpReassemblyTimeoutDetail{
				payloadFragment: 1,
			},
		},
		{
			name:                 "reassembly timeout (second fragment only)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:       []int{2},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv4TimeExceeded,
				code: header.ICMPv4ReassemblyTimeout,
			},
			expectErrorReply: false,
		},
		{
			name:                 "reassembly timeout (two fragments with a gap in reverse order)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 16,
			sendFrameOrder:       []int{1, 2},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv4TimeExceeded,
				code: header.ICMPv4ReassemblyTimeout,
			},
			expectErrorReply: true,
			expectICMPReassemblyTimeout: icmpReassemblyTimeoutDetail{
				payloadFragment: 1,
			},
		},
		{
			name:                 "reassembly timeout (two fragments with a gap)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 16,
			sendFrameOrder:       []int{2, 1},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv4TimeExceeded,
				code: header.ICMPv4ReassemblyTimeout,
			},
			expectErrorReply: true,
			expectICMPReassemblyTimeout: icmpReassemblyTimeoutDetail{
				payloadFragment: 1,
			},
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

			gotErrorMessage, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv4{},
				&testbench.ICMPv4{
					Type: testbench.ICMPv4Type(test.replyFilter.typ),
					Code: testbench.ICMPv4Code(test.replyFilter.code),
				},
			}, reassemblyTimeout)
			if !test.expectErrorReply {
				if err == nil {
					t.Fatalf("shouldn't receive an ICMPv4 Error Message with type=%d and code=%d", test.replyFilter.typ, test.replyFilter.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("didn't receive an ICMPv4 Error Message with type=%d and code=%d: %s", test.replyFilter.typ, test.replyFilter.code, err)
			}
			gotPayload, err := gotErrorMessage[len(gotErrorMessage)-1].ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv4 to bytes: %s", err)
			}
			icmpPayload := gotPayload[header.ICMPv4PayloadOffset:]
			wantPayload := ipv4Bytes[test.expectICMPReassemblyTimeout.payloadFragment-1]
			if diff := cmp.Diff(wantPayload, icmpPayload); diff != "" {
				t.Fatalf("payload mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
