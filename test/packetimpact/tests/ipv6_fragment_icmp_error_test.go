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

package ipv6_fragment_icmp_error_test

import (
	"flag"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	data              = "IPV6_PROTOCOL_TESTER_FOR_FRAGMENT"
	fragmentID        = 1
	reassemblyTimeout = ipv6.ReassembleTimeout + 5*time.Second
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func fragmentedICMPEchoRequest(t *testing.T, n *testbench.DUTTestNet, conn *testbench.IPv6Conn, firstPayloadLength uint16, payload []byte, secondFragmentOffset uint16) ([]testbench.Layers, [][]byte) {
	t.Helper()

	icmpv6Header := header.ICMPv6(make([]byte, header.ICMPv6EchoMinimumSize))
	icmpv6Header.SetType(header.ICMPv6EchoRequest)
	icmpv6Header.SetCode(header.ICMPv6UnusedCode)
	icmpv6Header.SetIdent(0)
	icmpv6Header.SetSequence(0)
	cksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpv6Header,
		Src:         tcpip.Address(n.LocalIPv6),
		Dst:         tcpip.Address(n.RemoteIPv6),
		PayloadCsum: header.Checksum(payload, 0 /* initial */),
		PayloadLen:  len(payload),
	})
	icmpv6Header.SetChecksum(cksum)
	icmpv6Bytes := append([]byte(icmpv6Header), payload...)

	icmpv6ProtoNum := header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber)

	firstFragment := conn.CreateFrame(t, testbench.Layers{&testbench.IPv6{}},
		&testbench.IPv6FragmentExtHdr{
			NextHeader:     &icmpv6ProtoNum,
			FragmentOffset: testbench.Uint16(0),
			MoreFragments:  testbench.Bool(true),
			Identification: testbench.Uint32(fragmentID),
		},
		&testbench.Payload{
			Bytes: icmpv6Bytes[:header.ICMPv6PayloadOffset+firstPayloadLength],
		},
	)
	firstIPv6 := firstFragment[1:]
	firstIPv6Bytes, err := firstIPv6.ToBytes()
	if err != nil {
		t.Fatalf("failed to convert first %s to bytes: %s", firstIPv6, err)
	}

	secondFragment := conn.CreateFrame(t, testbench.Layers{&testbench.IPv6{}},
		&testbench.IPv6FragmentExtHdr{
			NextHeader:     &icmpv6ProtoNum,
			FragmentOffset: testbench.Uint16(secondFragmentOffset),
			MoreFragments:  testbench.Bool(false),
			Identification: testbench.Uint32(fragmentID),
		},
		&testbench.Payload{
			Bytes: icmpv6Bytes[header.ICMPv6PayloadOffset+firstPayloadLength:],
		},
	)
	secondIPv6 := secondFragment[1:]
	secondIPv6Bytes, err := secondIPv6.ToBytes()
	if err != nil {
		t.Fatalf("failed to convert second %s to bytes: %s", secondIPv6, err)
	}

	return []testbench.Layers{firstFragment, secondFragment}, [][]byte{firstIPv6Bytes, secondIPv6Bytes}
}

func TestIPv6ICMPEchoRequestFragmentReassembly(t *testing.T) {
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
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{1, 2},
		},
		{
			name:                 "reassemble two fragments in reverse order",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{2, 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			fragments, _ := fragmentedICMPEchoRequest(t, dut.Net, &conn, test.firstPayloadLength, test.payload, test.secondFragmentOffset)

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			gotEchoReply, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv6{},
				&testbench.ICMPv6{
					Type: testbench.ICMPv6Type(header.ICMPv6EchoReply),
					Code: testbench.ICMPv6Code(header.ICMPv6UnusedCode),
				},
			}, time.Second)
			if err != nil {
				t.Fatalf("didn't receive an ICMPv6 Echo Reply: %s", err)
			}
			gotPayload, err := gotEchoReply[len(gotEchoReply)-1].ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv6 to bytes: %s", err)
			}
			icmpPayload := gotPayload[header.ICMPv6EchoMinimumSize:]
			wantPayload := test.payload
			if diff := cmp.Diff(wantPayload, icmpPayload); diff != "" {
				t.Fatalf("payload mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPv6FragmentReassemblyTimeout(t *testing.T) {
	type icmpFramePattern struct {
		typ  header.ICMPv6Type
		code header.ICMPv6Code
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
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{1},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv6TimeExceeded,
				code: header.ICMPv6ReassemblyTimeout,
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
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{2},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv6TimeExceeded,
				code: header.ICMPv6ReassemblyTimeout,
			},
			expectErrorReply: false,
		},
		{
			name:                 "reassembly timeout (two fragments with a gap)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 16) / 8,
			sendFrameOrder:       []int{1, 2},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv6TimeExceeded,
				code: header.ICMPv6ReassemblyTimeout,
			},
			expectErrorReply: true,
			expectICMPReassemblyTimeout: icmpReassemblyTimeoutDetail{
				payloadFragment: 1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			fragments, ipv6Bytes := fragmentedICMPEchoRequest(t, dut.Net, &conn, test.firstPayloadLength, test.payload, test.secondFragmentOffset)

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			gotErrorMessage, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv6{},
				&testbench.ICMPv6{
					Type: testbench.ICMPv6Type(test.replyFilter.typ),
					Code: testbench.ICMPv6Code(test.replyFilter.code),
				},
			}, reassemblyTimeout)
			if !test.expectErrorReply {
				if err == nil {
					t.Fatalf("shouldn't receive an ICMPv6 Error Message with type=%d and code=%d", test.replyFilter.typ, test.replyFilter.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("didn't receive an ICMPv6 Error Message with type=%d and code=%d: err", test.replyFilter.typ, test.replyFilter.code, err)
			}
			gotPayload, err := gotErrorMessage[len(gotErrorMessage)-1].ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv6 to bytes: %s", err)
			}
			icmpPayload := gotPayload[header.ICMPv6ErrorHeaderSize:]
			wantPayload := ipv6Bytes[test.expectICMPReassemblyTimeout.payloadFragment-1]
			if diff := cmp.Diff(wantPayload, icmpPayload); diff != "" {
				t.Fatalf("payload mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPv6FragmentParamProblem(t *testing.T) {
	type icmpFramePattern struct {
		typ  header.ICMPv6Type
		code header.ICMPv6Code
	}

	type icmpParamProblemDetail struct {
		pointer         uint32
		payloadFragment int // 1: first fragment, 2: second fragnemt.
	}

	tests := []struct {
		name                   string
		firstPayloadLength     uint16
		payload                []byte
		secondFragmentOffset   uint16
		sendFrameOrder         []int
		replyFilter            icmpFramePattern
		expectICMPParamProblem icmpParamProblemDetail
	}{
		{
			name:                 "payload size not a multiple of 8",
			firstPayloadLength:   9,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{1},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv6ParamProblem,
				code: header.ICMPv6ErroneousHeader,
			},
			expectICMPParamProblem: icmpParamProblemDetail{
				pointer:         4,
				payloadFragment: 1,
			},
		},
		{
			name:                 "payload length error",
			firstPayloadLength:   16,
			payload:              []byte(data)[:33],
			secondFragmentOffset: 65520 / 8,
			sendFrameOrder:       []int{1, 2},
			replyFilter: icmpFramePattern{
				typ:  header.ICMPv6ParamProblem,
				code: header.ICMPv6ErroneousHeader,
			},
			expectICMPParamProblem: icmpParamProblemDetail{
				pointer:         42,
				payloadFragment: 2,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dut := testbench.NewDUT(t)
			conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			fragments, ipv6Bytes := fragmentedICMPEchoRequest(t, dut.Net, &conn, test.firstPayloadLength, test.payload, test.secondFragmentOffset)

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			gotErrorMessage, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv6{},
				&testbench.ICMPv6{
					Type: testbench.ICMPv6Type(test.replyFilter.typ),
					Code: testbench.ICMPv6Code(test.replyFilter.code),
				},
			}, time.Second)
			if err != nil {
				t.Fatalf("didn't receive an ICMPv6 Error Message with type=%d and code=%d: err", test.replyFilter.typ, test.replyFilter.code, err)
			}
			gotPayload, err := gotErrorMessage[len(gotErrorMessage)-1].ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv6 to bytes: %s", err)
			}
			gotPointer := header.ICMPv6(gotPayload).TypeSpecific()
			wantPointer := test.expectICMPParamProblem.pointer
			if gotPointer != wantPointer {
				t.Fatalf("got pointer = %d, want = %d", gotPointer, wantPointer)
			}
			icmpPayload := gotPayload[header.ICMPv6ErrorHeaderSize:]
			wantPayload := ipv6Bytes[test.expectICMPParamProblem.payloadFragment-1]
			if diff := cmp.Diff(wantPayload, icmpPayload); diff != "" {
				t.Fatalf("payload mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
