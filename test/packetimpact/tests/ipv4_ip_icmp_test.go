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

package ipv4_sanity_test

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestIPv4Sanity(t *testing.T) {

	const (
		ttl            = 255
		nicID          = 1
		randomSequence = 123
		randomIdent    = 42
		maxPacketSize  = 1400
	)

	//	var (
	//		ipv4Addr = tcpip.AddressWithPrefix{
	//			Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
	//			PrefixLen: 24,
	//		}
	//		remoteIPv4Addr = tcpip.Address(net.ParseIP("10.0.0.1").To4())
	//	)

	tests := []struct {
		name                string
		headerLength        uint8 // value of 0 means "use correct size"
		badHeaderChecksum   bool
		maxTotalLength      uint16
		transportProtocol   uint8
		TTL                 uint8
		options             header.IPv4Options
		replyOptions        []byte // if succeeds, reply should look like this
		shouldFail          bool
		expectErrorICMP     bool
		ICMPType            header.ICMPv4Type
		ICMPCode            header.ICMPv4Code
		paramProblemPointer uint8
		trace               bool
	}{
		{
			name:              "valid no options",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
		},
		{
			name:              "bad header checksum",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			badHeaderChecksum: true,
			shouldFail:        true,
		},
		// The TTL tests check that we are not rejecting an incoming packet
		// with a zero or one TTL, which has been a point of confusion in the
		// past as RFC 791 says: "If this field contains the value zero, then the
		// datagram must be destroyed". However RFC 1122 section 3.2.1.7 clarifies
		// for the case of the destination host, stating as follows.
		//
		//      A host MUST NOT send a datagram with a Time-to-Live (TTL)
		//      value of zero.
		//
		//      A host MUST NOT discard a datagram just because it was
		//      received with TTL less than 2.
		{
			name:              "zero TTL",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               0,
		},
		{
			name:              "one TTL",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               1,
		},
		{
			name:              "End options",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{0, 0, 0, 0},
			replyOptions:      []byte{0, 0, 0, 0},
		},
		{
			name:              "NOP options",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{1, 1, 1, 1},
			replyOptions:      []byte{1, 1, 1, 1},
		},
		{
			name:              "NOP and End options",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{1, 1, 0, 0},
			replyOptions:      []byte{1, 1, 0, 0},
		},
		{
			name:              "bad header length",
			headerLength:      header.IPv4MinimumSize - 1,
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad total length (0)",
			maxTotalLength:    0,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad total length (ip - 1)",
			maxTotalLength:    uint16(header.IPv4MinimumSize - 1),
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad total length (ip + icmp - 1)",
			maxTotalLength:    uint16(header.IPv4MinimumSize + header.ICMPv4MinimumSize - 1),
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad protocol",
			maxTotalLength:    maxPacketSize,
			transportProtocol: 99,
			TTL:               ttl,
			shouldFail:        true,
			expectErrorICMP:   true,
			ICMPType:          header.ICMPv4DstUnreachable,
			ICMPCode:          header.ICMPv4ProtoUnreachable,
		},
		{
			name:              "timestamp option overflow",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			replyOptions: []byte{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
		},
		{
			name:              "timestamp option overflow full",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 12, 13, 0xF1,
				//            ^   Counter full (15/0xF)
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 3,
			replyOptions:        []byte{},
		},
		{
			name:              "unknown option",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{10, 4, 9, 0},
			//                        ^^
			// The unknown option should be stripped out of the reply.
			replyOptions: []byte{},
		},
		{
			name:              "bad option - length 0",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 0, 9, 0,
				//  ^
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 0, // was 1
		},
		{
			name:              "bad option - length big",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 9, 9, 0,
				//  ^
				// There are only 8 bytes allocated to options so 9 bytes of timestamp
				// space is not possible. (Second byte)
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 0, // was 1
		},
		{
			// This tests for some linux compatible behaviour.
			// The ICMP pointer returned is 22 for Linux but the
			// error is actually in spot 21.
			name:              "bad option - length bad",
			trace:             true,
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			// Timestamps are in multiples of 4 or 8 but never 7.
			// The option space should be padded out.
			options: []byte{
				68, 7, 5, 0,
				//  ^  ^ Linux points here which is wrong.
				//  | Not a multiple of 4
				1, 2, 3, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 2,
		},
		{
			name:              "multiple type 0 with room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 24, 21, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
			},
			replyOptions: []byte{
				68, 24, 25, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
		},
		{
			// The timestamp area is full so add to the overflow count.
			name:              "multiple type 1 timestamps",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 20, 21, 0x11,
				//            ^
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
			},
			// Overflow count is the top nibble of the 4th byte.
			replyOptions: []byte{
				68, 20, 21, 0x21,
				//            ^
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
			},
		},
		{
			name:              "multiple type 1 timestamps with room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 28, 21, 0x01,
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			replyOptions: []byte{
				68, 28, 29, 0x01,
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
				192, 168, 1, 58, // New IP Address.
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
		},
		{
			// Needs 8 bytes for a type 1 timestamp but there are only 4 free.
			name:              "bad timer element alignment",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 20, 17, 0x01,
				//  ^^  ^^   20 byte area, next free spot at 17.
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 2,
		},
		// End of option list with illegal option after it, which should be ignored.
		{
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 10, 3, 99,
			},
			replyOptions: []byte{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 0, 0, 0, // 3 bytes unknown option
			}, //   ^  End of options hides following bytes.
		},
		{
			// Timestamp with a size too small.
			name:              "timestamp truncated",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{68, 1, 0, 0},
			//                            ^ Smallest possible is 8.
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 0, // was 1
		},
		{
			name:              "single record route with room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				7, 7, 4, //  3 byte header
				0, 0, 0, 0,
				0,
			},
			replyOptions: []byte{
				7, 7, 8, // 3 byte header
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			name:              "multiple record route with room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				7, 23, 20, //  3 byte header
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
				0,
			},
			replyOptions: []byte{
				7, 23, 24,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			name:              "single record route with no room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0,
			},
			replyOptions: []byte{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Unlike timestamp, this should just succeed.
			name:              "multiple record route with no room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				7, 23, 24, // 3 byte header
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				0,
			},
			replyOptions: []byte{
				7, 23, 24,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Confirm linux bug for bug compatibility.
			// Linux returns slot 22 but the error is in slot 21.
			name:              "multiple record route with not enough room",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				7, 8, 8, // 3 byte header
				// ^  ^ Linux points here. We must too.
				// | Not enough room. 1 byte free, need 4.
				1, 2, 3, 4,
				0,
			},
			shouldFail:      true,
			expectErrorICMP: false, // was true
			// ICMPType:            header.ICMPv4ParamProblem,
			// ICMPCode:            header.ICMPv4UnusedCode,
			// paramProblemPointer: header.IPv4MinimumSize + 2,
		},
		{
			name:              "duplicate record route",
			maxTotalLength:    maxPacketSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: []byte{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0, 0, // pad
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			ipv4Conn := testbench.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			conn := (*testbench.Connection)(&ipv4Conn)
			defer ipv4Conn.Close(t)

			// if we want to override the checksum, IP header length or options we
			// need to know so up front as they are treated specially in the
			// testbench and/or ipv4.Encode
			var ipHeaderChecksum *uint16
			if test.badHeaderChecksum {
				ipHeaderChecksum = testbench.Uint16(42)
			}

			var ipHeaderLenPtr *uint8
			if test.headerLength != 0 {
				ipHeaderLenPtr = &test.headerLength
			}

			var ipHeaderLength int = header.IPv4MinimumSize
			var ipOptions *header.IPv4Options
			if test.options != nil && len(test.options) != 0 {
				ipOptions = &test.options
				ipHeaderLength += header.RoundUp4(len(test.options))
			}

			totalLen := uint16(ipHeaderLength + header.ICMPv4MinimumSize)
			if test.maxTotalLength < totalLen {
				totalLen = test.maxTotalLength
			}
			ipv4 := testbench.IPv4{
				IHL:         ipHeaderLenPtr,
				TotalLength: &totalLen,
				Protocol:    &test.transportProtocol,
				TTL:         &test.TTL,
				Checksum:    ipHeaderChecksum,
				Options:     ipOptions,
			}

			icmpv4 := testbench.ICMPv4{
				Type:     testbench.ICMPv4Type(header.ICMPv4Echo),
				Code:     testbench.ICMPv4Code(header.ICMPv4UnusedCode),
				Ident:    testbench.Uint16(randomIdent),
				Sequence: testbench.Uint16(randomSequence),
			}

			// create a frame using the outgoing layer stack from conn.
			// Note that it has not yet been interpretted int bytes.
			fullFrame := conn.CreateFrame(t, testbench.Layers{&ipv4}, &icmpv4)

			// 2nd and 3rd layers (ip + icmp)
			ipv4Frame := fullFrame[1:]

			// Keep a copy of this for later to compare to the payload of icmp errors.
			// Note it is Layers and thus we get ipv4 through payload if there is one.
			ipv4Bytes, err := ipv4Frame.ToBytes()
			if err != nil {
				t.Fatalf("can't convert %v to bytes: %s", ipv4Frame, err)
			}

			// Send the frame. This is where the description of a packet is turned
			// int an actual image of the packet.
			conn.SendFrame(t, fullFrame)

			// No matter what we get back, it should be ICMP.
			// There may be an ARP packet but it should be ignored.
			// We will not specifiy anything more than that at this stage.
			incomingFrame, err := ipv4Conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv4{},
				&testbench.ICMPv4{},
			}, time.Second)
			if err != nil {
				if test.shouldFail {
					if test.expectErrorICMP {
						t.Fatalf("ICMP error response (type %d, code %d) missing", test.ICMPType, test.ICMPCode)
					}
					if test.trace {
						fmt.Printf("expected failure\n")
					}
					return // Expected silent failure.
				}
				t.Fatal("expected ICMP echo reply missing")
			}

			if test.trace {
				fmt.Printf("expected packet\n")
			}
			// We didn't expect a packet. Register our surprise but carry on to
			// provide more information about what we got.
			if test.shouldFail && !test.expectErrorICMP {
				t.Error("unexpected packet response")
			}

			icmpLayer := incomingFrame[2]
			//icmpReply, err := icmpLayer.ToBytes()
			if err != nil {
				t.Fatalf("failed to parse ICMPv4 header: incomingPacket[2].ToBytes() = (_, %s)", err)
			}

			icmpHeader := icmpLayer.(*testbench.ICMPv4)

			switch *icmpHeader.Type {
			case header.ICMPv4EchoReply:
				if test.shouldFail {
					t.Fatalf("received unexpected echo response")
				}
			case header.ICMPv4Echo:
				t.Fatalf("received unexpected echo request")

			case header.ICMPv4ParamProblem:
				if got, want := *icmpHeader.Pointer, test.paramProblemPointer; got != want {
					t.Errorf("got PP pointer %d, want %d", got, want)
				}
				fallthrough
			default:
				if !test.shouldFail {
					t.Fatalf("received unexpected error response")
				}
				if *icmpHeader.Type != test.ICMPType || *icmpHeader.Code != test.ICMPCode {
					t.Errorf("got ICMP(type=%d, code=%d), want (%d, %d)",
						*icmpHeader.Type, *icmpHeader.Code,
						test.ICMPType, test.ICMPCode)
				}

				if !bytes.Equal(icmpHeader.Payload, ipv4Bytes) {
					t.Errorf("received unexpected payload, got: %s, want: %s",
						hex.Dump(icmpHeader.Payload),
						hex.Dump(ipv4Bytes))
				}
			}
		})
	}
}
