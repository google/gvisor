// Copyright 2021 The gVisor Authors.
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

package ipv4_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	extraHeaderReserve = 50
	defaultMTU         = 65536
)

func TestExcludeBroadcast(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})

	ep := stack.LinkEndpoint(channel.New(256, defaultMTU, ""))
	if testing.Verbose() {
		ep = sniffer.New(ep)
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	}})

	randomAddr := tcpip.FullAddress{NIC: 1, Addr: "\x0a\x00\x00\x01", Port: 53}

	var wq waiter.Queue
	t.Run("WithoutPrimaryAddress", func(t *testing.T) {
		ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()

		// Cannot connect using a broadcast address as the source.
		if err := ep.Connect(randomAddr); err != tcpip.ErrNoRoute {
			t.Errorf("got ep.Connect(...) = %v, want = %v", err, tcpip.ErrNoRoute)
		}

		// However, we can bind to a broadcast address to listen.
		if err := ep.Bind(tcpip.FullAddress{Addr: header.IPv4Broadcast, Port: 53, NIC: 1}); err != nil {
			t.Errorf("Bind failed: %v", err)
		}
	})

	t.Run("WithPrimaryAddress", func(t *testing.T) {
		ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()

		// Add a valid primary endpoint address, now we can connect.
		if err := s.AddAddress(1, ipv4.ProtocolNumber, "\x0a\x00\x00\x02"); err != nil {
			t.Fatalf("AddAddress failed: %v", err)
		}
		if err := ep.Connect(randomAddr); err != nil {
			t.Errorf("Connect failed: %v", err)
		}
	})
}

func TestForwarding(t *testing.T) {
	const (
		nicID1         = 1
		nicID2         = 2
		randomSequence = 123
		randomIdent    = 42
	)

	ipv4Addr1 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("10.0.0.1").To4()),
		PrefixLen: 8,
	}
	ipv4Addr2 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("11.0.0.1").To4()),
		PrefixLen: 8,
	}
	remoteIPv4Addr1 := tcpip.Address(net.ParseIP("10.0.0.2").To4())
	remoteIPv4Addr2 := tcpip.Address(net.ParseIP("11.0.0.2").To4())

	tests := []struct {
		name            string
		TTL             uint8
		expectErrorICMP bool
	}{
		{
			name:            "TTL of zero",
			TTL:             0,
			expectErrorICMP: true,
		},
		{
			name:            "TTL of one",
			TTL:             1,
			expectErrorICMP: false,
		},
		{
			name:            "TTL of two",
			TTL:             2,
			expectErrorICMP: false,
		},
		{
			name:            "Max TTL",
			TTL:             math.MaxUint8,
			expectErrorICMP: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
			})
			// We expect at most a single packet in response to our ICMP Echo Request.
			e1 := channel.New(1, ipv4.MaxTotalSize, "")
			if err := s.CreateNIC(nicID1, e1); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
			}
			ipv4ProtoAddr1 := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr1}
			if err := s.AddProtocolAddress(nicID1, ipv4ProtoAddr1); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID1, ipv4ProtoAddr1, err)
			}

			e2 := channel.New(1, ipv4.MaxTotalSize, "")
			if err := s.CreateNIC(nicID2, e2); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID2, err)
			}
			ipv4ProtoAddr2 := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr2}
			if err := s.AddProtocolAddress(nicID2, ipv4ProtoAddr2); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID2, ipv4ProtoAddr2, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: ipv4Addr1.Subnet(),
					NIC:         nicID1,
				},
				{
					Destination: ipv4Addr2.Subnet(),
					NIC:         nicID2,
				},
			})

			if err := s.SetForwarding(header.IPv4ProtocolNumber, true); err != nil {
				t.Fatalf("SetForwarding(%d, true): %s", header.IPv4ProtocolNumber, err)
			}

			totalLen := uint16(header.IPv4MinimumSize + header.ICMPv4MinimumSize)
			hdr := buffer.NewPrependable(int(totalLen))
			icmp := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
			icmp.SetIdent(randomIdent)
			icmp.SetSequence(randomSequence)
			icmp.SetType(header.ICMPv4Echo)
			icmp.SetCode(header.ICMPv4UnusedCode)
			icmp.SetChecksum(0)
			icmp.SetChecksum(^header.Checksum(icmp, 0))
			ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
			ip.Encode(&header.IPv4Fields{
				TotalLength: totalLen,
				Protocol:    uint8(header.ICMPv4ProtocolNumber),
				TTL:         test.TTL,
				SrcAddr:     remoteIPv4Addr1,
				DstAddr:     remoteIPv4Addr2,
			})
			ip.SetChecksum(0)
			ip.SetChecksum(^ip.CalculateChecksum())
			requestPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			})
			e1.InjectInbound(header.IPv4ProtocolNumber, requestPkt)

			if test.expectErrorICMP {
				reply, ok := e1.Read()
				if !ok {
					t.Fatal("expected ICMP TTL Exceeded packet through incoming NIC")
				}

				checker.IPv4(t, header.IPv4(stack.PayloadSince(reply.Pkt.NetworkHeader())),
					checker.SrcAddr(ipv4Addr1.Address),
					checker.DstAddr(remoteIPv4Addr1),
					checker.TTL(ipv4.DefaultTTL),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Type(header.ICMPv4TimeExceeded),
						checker.ICMPv4Code(header.ICMPv4TTLExceeded),
						checker.ICMPv4Payload([]byte(hdr.View())),
					),
				)

				if n := e2.Drain(); n != 0 {
					t.Fatalf("got e2.Drain() = %d, want = 0", n)
				}
			} else {
				reply, ok := e2.Read()
				if !ok {
					t.Fatal("expected ICMP Echo packet through outgoing NIC")
				}

				checker.IPv4(t, header.IPv4(stack.PayloadSince(reply.Pkt.NetworkHeader())),
					checker.SrcAddr(remoteIPv4Addr1),
					checker.DstAddr(remoteIPv4Addr2),
					checker.TTL(test.TTL-1),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Type(header.ICMPv4Echo),
						checker.ICMPv4Code(header.ICMPv4UnusedCode),
						checker.ICMPv4Payload(nil),
					),
				)

				if n := e1.Drain(); n != 0 {
					t.Fatalf("got e1.Drain() = %d, want = 0", n)
				}
			}
		})
	}
}

// TestIPv4Sanity sends IP/ICMP packets with various problems to the stack and
// checks the response.
func TestIPv4Sanity(t *testing.T) {
	const (
		ttl            = 255
		nicID          = 1
		randomSequence = 123
		randomIdent    = 42
		// In some cases Linux sets the error pointer to the start of the option
		// (offset 0) instead of the actual wrong value, which is the length byte
		// (offset 1). For compatibility we must do the same. Use this constant
		// to indicate where this happens.
		pointerOffsetForInvalidLength = 0
	)
	var (
		ipv4Addr = tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
			PrefixLen: 24,
		}
		remoteIPv4Addr = tcpip.Address(net.ParseIP("10.0.0.1").To4())
	)

	tests := []struct {
		name                string
		headerLength        uint8 // value of 0 means "use correct size"
		badHeaderChecksum   bool
		maxTotalLength      uint16
		transportProtocol   uint8
		TTL                 uint8
		options             header.IPv4Options
		replyOptions        header.IPv4Options // reply should look like this
		shouldFail          bool
		expectErrorICMP     bool
		ICMPType            header.ICMPv4Type
		ICMPCode            header.ICMPv4Code
		paramProblemPointer uint8
	}{
		{
			name:              "valid no options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
		},
		{
			name:              "bad header checksum",
			maxTotalLength:    ipv4.MaxTotalSize,
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
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               0,
		},
		{
			name:              "one TTL",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               1,
		},
		{
			name:              "End options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{0, 0, 0, 0},
			replyOptions:      header.IPv4Options{0, 0, 0, 0},
		},
		{
			name:              "NOP options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{1, 1, 1, 1},
			replyOptions:      header.IPv4Options{1, 1, 1, 1},
		},
		{
			name:              "NOP and End options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{1, 1, 0, 0},
			replyOptions:      header.IPv4Options{1, 1, 0, 0},
		},
		{
			name:              "bad header length",
			headerLength:      header.IPv4MinimumSize - 1,
			maxTotalLength:    ipv4.MaxTotalSize,
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
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: 99,
			TTL:               ttl,
			shouldFail:        true,
			expectErrorICMP:   true,
			ICMPType:          header.ICMPv4DstUnreachable,
			ICMPCode:          header.ICMPv4ProtoUnreachable,
		},
		{
			name:              "timestamp option overflow",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			replyOptions: header.IPv4Options{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
		},
		{
			name:              "timestamp option overflow full",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
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
			replyOptions:        header.IPv4Options{},
		},
		{
			name:              "unknown option",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{10, 4, 9, 0},
			//                        ^^
			// The unknown option should be stripped out of the reply.
			replyOptions: header.IPv4Options{},
		},
		{
			name:              "bad option - no length",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				1, 1, 1, 68,
				//        ^-start of timestamp.. but no length..
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 3,
		},
		{
			name:              "bad option - length 0",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 0, 9, 0,
				//  ^
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			name:              "bad option - length 1",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 1, 9, 0,
				//  ^
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			name:              "bad option - length big",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
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
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			// This tests for some linux compatible behaviour.
			// The ICMP pointer returned is 22 for Linux but the
			// error is actually in spot 21.
			name:              "bad option - length bad",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			// Timestamps are in multiples of 4 or 8 but never 7.
			// The option space should be padded out.
			options: header.IPv4Options{
				68, 7, 5, 0,
				//  ^  ^ Linux points here which is wrong.
				//  | Not a multiple of 4
				1, 2, 3, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptTSPointerOffset,
		},
		{
			name:              "multiple type 0 with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 24, 21, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
			},
			replyOptions: header.IPv4Options{
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
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 20, 21, 0x11,
				//            ^
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
			},
			// Overflow count is the top nibble of the 4th byte.
			replyOptions: header.IPv4Options{
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
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 28, 21, 0x01,
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			replyOptions: header.IPv4Options{
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
			// Timestamp pointer uses one based counting so 0 is invalid.
			name:              "timestamp pointer invalid",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 8, 0, 0x00,
				//      ^ 0 instead of 5 or more.
				0, 0, 0, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 2,
		},
		{
			// Timestamp pointer cannot be less than 5. It must point past the header
			// which is 4 bytes. (1 based counting)
			name:              "timestamp pointer too small by 1",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 8, header.IPv4OptionTimestampHdrLength, 0x00,
				//          ^ header is 4 bytes, so 4 should fail.
				0, 0, 0, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptTSPointerOffset,
		},
		{
			name:              "valid timestamp pointer",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 8, header.IPv4OptionTimestampHdrLength + 1, 0x00,
				//          ^ header is 4 bytes, so 5 should succeed.
				0, 0, 0, 0,
			},
			replyOptions: header.IPv4Options{
				68, 8, 9, 0x00,
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
		},
		{
			// Needs 8 bytes for a type 1 timestamp but there are only 4 free.
			name:              "bad timer element alignment",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
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
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptTSPointerOffset,
		},
		// End of option list with illegal option after it, which should be ignored.
		{
			name:              "end of options list",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 10, 3, 99, // EOL followed by junk
			},
			replyOptions: header.IPv4Options{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0,       // End of Options hides following bytes.
				0, 0, 0, // 3 bytes unknown option removed.
			},
		},
		{
			// Timestamp with a size much too small.
			name:              "timestamp truncated",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 1, 0, 0,
				//  ^ Smallest possible is 8. Linux points at the 68.
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			name:              "single record route with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, 4, //  3 byte header
				0, 0, 0, 0,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 7, 8, // 3 byte header
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			name:              "multiple record route with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 23, 20, //  3 byte header
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
				0,
			},
			replyOptions: header.IPv4Options{
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
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Unlike timestamp, this should just succeed.
			name:              "multiple record route with no room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 23, 24, // 3 byte header
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				0,
			},
			replyOptions: header.IPv4Options{
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
			// Pointer uses one based counting so 0 is invalid.
			name:              "record route pointer zero",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 8, 0, // 3 byte header
				0, 0, 0, 0,
				0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptRRPointerOffset,
		},
		{
			// Pointer must be 4 or more as it must point past the 3 byte header
			// using 1 based counting. 3 should fail.
			name:              "record route pointer too small by 1",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 8, header.IPv4OptionRecordRouteHdrLength, // 3 byte header
				0, 0, 0, 0,
				0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptRRPointerOffset,
		},
		{
			// Pointer must be 4 or more as it must point past the 3 byte header
			// using 1 based counting. Check 4 passes. (Duplicates "single
			// record route with room")
			name:              "valid record route pointer",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, header.IPv4OptionRecordRouteHdrLength + 1, // 3 byte header
				0, 0, 0, 0,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 7, 8, // 3 byte header
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Confirm Linux bug for bug compatibility.
			// Linux returns slot 22 but the error is in slot 21.
			name:              "multiple record route with not enough room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 8, 8, // 3 byte header
				// ^  ^ Linux points here. We must too.
				// | Not enough room. 1 byte free, need 4.
				1, 2, 3, 4,
				0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptRRPointerOffset,
		},
		{
			name:              "duplicate record route",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
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
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
				Clock:              clock,
			})
			// We expect at most a single packet in response to our ICMP Echo Request.
			e := channel.New(1, ipv4.MaxTotalSize, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			ipv4ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr}
			if err := s.AddProtocolAddress(nicID, ipv4ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, ipv4ProtoAddr, err)
			}
			// Advance the clock by some unimportant amount to make
			// sure it's all set up.
			clock.Advance(time.Millisecond * 0x10203040)

			// Default routes for IPv4 so ICMP can find a route to the remote
			// node when attempting to send the ICMP Echo Reply.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			if len(test.options)%4 != 0 {
				t.Fatalf("options must be aligned to 32 bits, invalid test options: %x (len=%d)", test.options, len(test.options))
			}
			ipHeaderLength := header.IPv4MinimumSize + len(test.options)
			if ipHeaderLength > header.IPv4MaximumHeaderSize {
				t.Fatalf("IP header length too large: got = %d, want <= %d ", ipHeaderLength, header.IPv4MaximumHeaderSize)
			}
			totalLen := uint16(ipHeaderLength + header.ICMPv4MinimumSize)
			hdr := buffer.NewPrependable(int(totalLen))
			icmp := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))

			// Specify ident/seq to make sure we get the same in the response.
			icmp.SetIdent(randomIdent)
			icmp.SetSequence(randomSequence)
			icmp.SetType(header.ICMPv4Echo)
			icmp.SetCode(header.ICMPv4UnusedCode)
			icmp.SetChecksum(0)
			icmp.SetChecksum(^header.Checksum(icmp, 0))
			ip := header.IPv4(hdr.Prepend(ipHeaderLength))
			if test.maxTotalLength < totalLen {
				totalLen = test.maxTotalLength
			}
			ip.Encode(&header.IPv4Fields{
				TotalLength: totalLen,
				Protocol:    test.transportProtocol,
				TTL:         test.TTL,
				SrcAddr:     remoteIPv4Addr,
				DstAddr:     ipv4Addr.Address,
			})
			if test.headerLength != 0 {
				ip.SetHeaderLength(test.headerLength)
			} else {
				// Set the calculated header length, since we may manually add options.
				ip.SetHeaderLength(uint8(ipHeaderLength))
			}
			if len(test.options) != 0 {
				// Copy options manually. We do not use Encode for options so we can
				// verify malformed options with handcrafted payloads.
				if want, got := copy(ip.Options(), test.options), len(test.options); want != got {
					t.Fatalf("got copy(ip.Options(), test.options) = %d, want = %d", got, want)
				}
			}
			ip.SetChecksum(0)
			ipHeaderChecksum := ip.CalculateChecksum()
			if test.badHeaderChecksum {
				ipHeaderChecksum += 42
			}
			ip.SetChecksum(^ipHeaderChecksum)
			requestPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			})
			e.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply, ok := e.Read()
			if !ok {
				if test.shouldFail {
					if test.expectErrorICMP {
						t.Fatalf("ICMP error response (type %d, code %d) missing", test.ICMPType, test.ICMPCode)
					}
					return // Expected silent failure.
				}
				t.Fatal("expected ICMP echo reply missing")
			}

			// We didn't expect a packet. Register our surprise but carry on to
			// provide more information about what we got.
			if test.shouldFail && !test.expectErrorICMP {
				t.Error("unexpected packet response")
			}

			// Check the route that brought the packet to us.
			if reply.Route.LocalAddress != ipv4Addr.Address {
				t.Errorf("got pkt.Route.LocalAddress = %s, want = %s", reply.Route.LocalAddress, ipv4Addr.Address)
			}
			if reply.Route.RemoteAddress != remoteIPv4Addr {
				t.Errorf("got pkt.Route.RemoteAddress = %s, want = %s", reply.Route.RemoteAddress, remoteIPv4Addr)
			}

			// Make sure it's all in one buffer for checker.
			replyIPHeader := header.IPv4(stack.PayloadSince(reply.Pkt.NetworkHeader()))

			// At this stage we only know it's probably an IP+ICMP header so verify
			// that much.
			checker.IPv4(t, replyIPHeader,
				checker.SrcAddr(ipv4Addr.Address),
				checker.DstAddr(remoteIPv4Addr),
				checker.ICMPv4(
					checker.ICMPv4Checksum(),
				),
			)

			// Don't proceed any further if the checker found problems.
			if t.Failed() {
				t.FailNow()
			}

			// OK it's ICMP. We can safely look at the type now.
			replyICMPHeader := header.ICMPv4(replyIPHeader.Payload())
			switch replyICMPHeader.Type() {
			case header.ICMPv4ParamProblem:
				if !test.shouldFail {
					t.Fatalf("got Parameter Problem with pointer %d, wanted Echo Reply", replyICMPHeader.Pointer())
				}
				if !test.expectErrorICMP {
					t.Fatalf("got Parameter Problem with pointer %d, wanted no response", replyICMPHeader.Pointer())
				}
				checker.IPv4(t, replyIPHeader,
					checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+requestPkt.Size())),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.ICMPv4(
						checker.ICMPv4Type(test.ICMPType),
						checker.ICMPv4Code(test.ICMPCode),
						checker.ICMPv4Pointer(test.paramProblemPointer),
						checker.ICMPv4Payload([]byte(hdr.View())),
					),
				)
				return
			case header.ICMPv4DstUnreachable:
				if !test.shouldFail {
					t.Fatalf("got ICMP error packet type %d, code %d, wanted Echo Reply",
						header.ICMPv4DstUnreachable, replyICMPHeader.Code())
				}
				if !test.expectErrorICMP {
					t.Fatalf("got ICMP error packet type %d, code %d, wanted no response",
						header.ICMPv4DstUnreachable, replyICMPHeader.Code())
				}
				checker.IPv4(t, replyIPHeader,
					checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+requestPkt.Size())),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.ICMPv4(
						checker.ICMPv4Type(test.ICMPType),
						checker.ICMPv4Code(test.ICMPCode),
						checker.ICMPv4Payload([]byte(hdr.View())),
					),
				)
				return
			case header.ICMPv4EchoReply:
				if test.shouldFail {
					if !test.expectErrorICMP {
						t.Error("got Echo Reply packet, want no response")
					} else {
						t.Errorf("got Echo Reply, want ICMP error type %d, code %d", test.ICMPType, test.ICMPCode)
					}
				}
				// If the IP options change size then the packet will change size, so
				// some IP header fields will need to be adjusted for the checks.
				sizeChange := len(test.replyOptions) - len(test.options)

				checker.IPv4(t, replyIPHeader,
					checker.IPv4HeaderLength(ipHeaderLength+sizeChange),
					checker.IPv4Options(test.replyOptions),
					checker.IPFullLength(uint16(requestPkt.Size()+sizeChange)),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Code(header.ICMPv4UnusedCode),
						checker.ICMPv4Seq(randomSequence),
						checker.ICMPv4Ident(randomIdent),
					),
				)
			default:
				t.Fatalf("unexpected ICMP response, got type %d, want = %d, %d or %d",
					replyICMPHeader.Type(), header.ICMPv4EchoReply, header.ICMPv4DstUnreachable, header.ICMPv4ParamProblem)
			}
		})
	}
}

// comparePayloads compared the contents of all the packets against the contents
// of the source packet.
func compareFragments(packets []*stack.PacketBuffer, sourcePacket *stack.PacketBuffer, mtu uint32, wantFragments []fragmentInfo, proto tcpip.TransportProtocolNumber) error {
	// Make a complete array of the sourcePacket packet.
	source := header.IPv4(packets[0].NetworkHeader().View())
	vv := buffer.NewVectorisedView(sourcePacket.Size(), sourcePacket.Views())
	source = append(source, vv.ToView()...)

	// Make a copy of the IP header, which will be modified in some fields to make
	// an expected header.
	sourceCopy := header.IPv4(append(buffer.View(nil), source[:source.HeaderLength()]...))
	sourceCopy.SetChecksum(0)
	sourceCopy.SetFlagsFragmentOffset(0, 0)
	sourceCopy.SetTotalLength(0)
	// Build up an array of the bytes sent.
	var reassembledPayload buffer.VectorisedView
	for i, packet := range packets {
		// Confirm that the packet is valid.
		allBytes := buffer.NewVectorisedView(packet.Size(), packet.Views())
		fragmentIPHeader := header.IPv4(allBytes.ToView())
		if !fragmentIPHeader.IsValid(len(fragmentIPHeader)) {
			return fmt.Errorf("fragment #%d: IP packet is invalid:\n%s", i, hex.Dump(fragmentIPHeader))
		}
		if got := len(fragmentIPHeader); got > int(mtu) {
			return fmt.Errorf("fragment #%d: got len(fragmentIPHeader) = %d, want <= %d", i, got, mtu)
		}
		if got := fragmentIPHeader.TransportProtocol(); got != proto {
			return fmt.Errorf("fragment #%d: got fragmentIPHeader.TransportProtocol() = %d, want = %d", i, got, uint8(proto))
		}
		if got := packet.AvailableHeaderBytes(); got != extraHeaderReserve {
			return fmt.Errorf("fragment #%d: got packet.AvailableHeaderBytes() = %d, want = %d", i, got, extraHeaderReserve)
		}
		if got, want := packet.NetworkProtocolNumber, sourcePacket.NetworkProtocolNumber; got != want {
			return fmt.Errorf("fragment #%d: got fragment.NetworkProtocolNumber = %d, want = %d", i, got, want)
		}
		if got, want := fragmentIPHeader.CalculateChecksum(), uint16(0xffff); got != want {
			return fmt.Errorf("fragment #%d: got ip.CalculateChecksum() = %#x, want = %#x", i, got, want)
		}
		if wantFragments[i].more {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()|header.IPv4FlagMoreFragments, wantFragments[i].offset)
		} else {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()&^header.IPv4FlagMoreFragments, wantFragments[i].offset)
		}
		reassembledPayload.AppendView(packet.TransportHeader().View())
		reassembledPayload.Append(packet.Data)
		// Clear out the checksum and length from the ip because we can't compare
		// it.
		sourceCopy.SetTotalLength(wantFragments[i].payloadSize + header.IPv4MinimumSize)
		sourceCopy.SetChecksum(0)
		sourceCopy.SetChecksum(^sourceCopy.CalculateChecksum())
		if diff := cmp.Diff(fragmentIPHeader[:fragmentIPHeader.HeaderLength()], sourceCopy[:sourceCopy.HeaderLength()]); diff != "" {
			return fmt.Errorf("fragment #%d: fragmentIPHeader mismatch (-want +got):\n%s", i, diff)
		}
	}

	expected := buffer.View(source[source.HeaderLength():])
	if diff := cmp.Diff(expected, reassembledPayload.ToView()); diff != "" {
		return fmt.Errorf("reassembledPayload mismatch (-want +got):\n%s", diff)
	}

	return nil
}

type fragmentInfo struct {
	offset      uint16
	more        bool
	payloadSize uint16
}

var fragmentationTests = []struct {
	description           string
	mtu                   uint32
	gso                   *stack.GSO
	transportHeaderLength int
	payloadSize           int
	wantFragments         []fragmentInfo
}{
	{
		description:           "No fragmentation",
		mtu:                   1280,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1000, more: false},
		},
	},
	{
		description:           "Fragmented",
		mtu:                   1280,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           2000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 744, more: false},
		},
	},
	{
		description:           "Fragmented with the minimum mtu",
		mtu:                   header.IPv4MinimumMTU,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           100,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 48, more: true},
			{offset: 48, payloadSize: 48, more: true},
			{offset: 96, payloadSize: 4, more: false},
		},
	},
	{
		description:           "Fragmented with mtu not a multiple of 8",
		mtu:                   header.IPv4MinimumMTU + 1,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           100,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 48, more: true},
			{offset: 48, payloadSize: 48, more: true},
			{offset: 96, payloadSize: 4, more: false},
		},
	},
	{
		description:           "No fragmentation with big header",
		mtu:                   2000,
		gso:                   nil,
		transportHeaderLength: 100,
		payloadSize:           1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1100, more: false},
		},
	},
	{
		description:           "Fragmented with gso none",
		mtu:                   1280,
		gso:                   &stack.GSO{Type: stack.GSONone},
		transportHeaderLength: 0,
		payloadSize:           1400,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 144, more: false},
		},
	},
	{
		description:           "Fragmented with big header",
		mtu:                   1280,
		gso:                   nil,
		transportHeaderLength: 100,
		payloadSize:           1200,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 44, more: false},
		},
	},
	{
		description:           "Fragmented with MTU smaller than header",
		mtu:                   300,
		gso:                   nil,
		transportHeaderLength: 1000,
		payloadSize:           500,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 280, more: true},
			{offset: 280, payloadSize: 280, more: true},
			{offset: 560, payloadSize: 280, more: true},
			{offset: 840, payloadSize: 280, more: true},
			{offset: 1120, payloadSize: 280, more: true},
			{offset: 1400, payloadSize: 100, more: false},
		},
	},
}

func TestFragmentationWritePacket(t *testing.T) {
	const ttl = 42

	for _, ft := range fragmentationTests {
		t.Run(ft.description, func(t *testing.T) {
			ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
			r := buildRoute(t, ep)
			pkt := testutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
			source := pkt.Clone()
			err := r.WritePacket(ft.gso, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != nil {
				t.Fatalf("r.WritePacket(_, _, _) = %s", err)
			}
			if got := len(ep.WrittenPackets); got != len(ft.wantFragments) {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, len(ft.wantFragments))
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != len(ft.wantFragments) {
				t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, len(ft.wantFragments))
			}
			if got := r.Stats().IP.OutgoingPacketErrors.Value(); got != 0 {
				t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = 0", got)
			}
			if err := compareFragments(ep.WrittenPackets, source, ft.mtu, ft.wantFragments, tcp.ProtocolNumber); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestFragmentationWritePackets(t *testing.T) {
	const ttl = 42
	writePacketsTests := []struct {
		description  string
		insertBefore int
		insertAfter  int
	}{
		{
			description:  "Single packet",
			insertBefore: 0,
			insertAfter:  0,
		},
		{
			description:  "With packet before",
			insertBefore: 1,
			insertAfter:  0,
		},
		{
			description:  "With packet after",
			insertBefore: 0,
			insertAfter:  1,
		},
		{
			description:  "With packet before and after",
			insertBefore: 1,
			insertAfter:  1,
		},
	}
	tinyPacket := testutil.MakeRandPkt(header.TCPMinimumSize, extraHeaderReserve+header.IPv4MinimumSize, []int{1}, header.IPv4ProtocolNumber)

	for _, test := range writePacketsTests {
		t.Run(test.description, func(t *testing.T) {
			for _, ft := range fragmentationTests {
				t.Run(ft.description, func(t *testing.T) {
					var pkts stack.PacketBufferList
					for i := 0; i < test.insertBefore; i++ {
						pkts.PushBack(tinyPacket.Clone())
					}
					pkt := testutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
					pkts.PushBack(pkt.Clone())
					for i := 0; i < test.insertAfter; i++ {
						pkts.PushBack(tinyPacket.Clone())
					}

					ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
					r := buildRoute(t, ep)

					wantTotalPackets := len(ft.wantFragments) + test.insertBefore + test.insertAfter
					n, err := r.WritePackets(ft.gso, pkts, stack.NetworkHeaderParams{
						Protocol: tcp.ProtocolNumber,
						TTL:      ttl,
						TOS:      stack.DefaultTOS,
					})
					if err != nil {
						t.Errorf("got WritePackets(_, _, _) = (_, %s), want = (_, nil)", err)
					}
					if n != wantTotalPackets {
						t.Errorf("got WritePackets(_, _, _) = (%d, _), want = (%d, _)", n, wantTotalPackets)
					}
					if got := len(ep.WrittenPackets); got != wantTotalPackets {
						t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, wantTotalPackets)
					}
					if got := int(r.Stats().IP.PacketsSent.Value()); got != wantTotalPackets {
						t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, wantTotalPackets)
					}
					if got := int(r.Stats().IP.OutgoingPacketErrors.Value()); got != 0 {
						t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = 0", got)
					}

					if wantTotalPackets == 0 {
						return
					}

					fragments := ep.WrittenPackets[test.insertBefore : len(ft.wantFragments)+test.insertBefore]
					if err := compareFragments(fragments, pkt, ft.mtu, ft.wantFragments, tcp.ProtocolNumber); err != nil {
						t.Error(err)
					}
				})
			}
		})
	}
}

// TestFragmentationErrors checks that errors are returned from WritePacket
// correctly.
func TestFragmentationErrors(t *testing.T) {
	const ttl = 42

	tests := []struct {
		description           string
		mtu                   uint32
		transportHeaderLength int
		payloadSize           int
		allowPackets          int
		outgoingErrors        int
		mockError             *tcpip.Error
		wantError             *tcpip.Error
	}{
		{
			description:           "No frag",
			mtu:                   2000,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          0,
			outgoingErrors:        1,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error on first frag",
			mtu:                   500,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          0,
			outgoingErrors:        3,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error on second frag",
			mtu:                   500,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          1,
			outgoingErrors:        2,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error on first frag MTU smaller than header",
			mtu:                   500,
			transportHeaderLength: 1000,
			payloadSize:           500,
			allowPackets:          0,
			outgoingErrors:        4,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error when MTU is smaller than IPv4 minimum MTU",
			mtu:                   header.IPv4MinimumMTU - 1,
			transportHeaderLength: 0,
			payloadSize:           500,
			allowPackets:          0,
			outgoingErrors:        1,
			mockError:             nil,
			wantError:             tcpip.ErrInvalidEndpointState,
		},
	}

	for _, ft := range tests {
		t.Run(ft.description, func(t *testing.T) {
			pkt := testutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
			ep := testutil.NewMockLinkEndpoint(ft.mtu, ft.mockError, ft.allowPackets)
			r := buildRoute(t, ep)
			err := r.WritePacket(&stack.GSO{}, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != ft.wantError {
				t.Errorf("got WritePacket(_, _, _) = %s, want = %s", err, ft.wantError)
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != ft.allowPackets {
				t.Errorf("got r.Stats().IP.PacketsSent.Value() = %d, want = %d", got, ft.allowPackets)
			}
			if got := int(r.Stats().IP.OutgoingPacketErrors.Value()); got != ft.outgoingErrors {
				t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = %d", got, ft.outgoingErrors)
			}
		})
	}
}

func TestInvalidFragments(t *testing.T) {
	const (
		nicID    = 1
		linkAddr = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		addr1    = "\x0a\x00\x00\x01"
		addr2    = "\x0a\x00\x00\x02"
		tos      = 0
		ident    = 1
		ttl      = 48
		protocol = 6
	)

	payloadGen := func(payloadLen int) []byte {
		payload := make([]byte, payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = 0x30
		}
		return payload
	}

	type fragmentData struct {
		ipv4fields header.IPv4Fields
		// 0 means insert the correct IHL. Non 0 means override the correct IHL.
		overrideIHL  int // For 0 use 1 as it is an int and will be divided by 4.
		payload      []byte
		autoChecksum bool // If true, the Checksum field will be overwritten.
	}

	tests := []struct {
		name                   string
		fragments              []fragmentData
		wantMalformedIPPackets uint64
		wantMalformedFragments uint64
	}{
		{
			name: "IHL and TotalLength zero, FragmentOffset non-zero",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    0,
						ID:             ident,
						Flags:          header.IPv4FlagDontFragment | header.IPv4FlagMoreFragments,
						FragmentOffset: 59776,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					overrideIHL:  1, // See note above.
					payload:      payloadGen(12),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 0,
		},
		{
			name: "IHL and TotalLength zero, FragmentOffset zero",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    0,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					overrideIHL:  1, // See note above.
					payload:      payloadGen(12),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 0,
		},
		{
			// Payload 17 octets and Fragment offset 65520
			// Leading to the fragment end to be past 65536.
			name: "fragment ends past 65536",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 17,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 65520,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(17),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
		{
			// Payload 16 octets and fragment offset 65520
			// Leading to the fragment end to be exactly 65536.
			name: "fragment ends exactly at 65536",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 65520,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(16),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 0,
			wantMalformedFragments: 0,
		},
		{
			name: "IHL less than IPv4 minimum size",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 28,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 1944,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize - 12,
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize - 12,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize - 12,
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 2,
			wantMalformedFragments: 0,
		},
		{
			name: "fragment with short TotalLength and extra payload",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 28,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 28816,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize + 4,
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 4,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize + 4,
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
		{
			name: "multiple fragments with More Fragments flag set to false",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 128,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 8,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{
					ipv4.NewProtocol,
				},
			})
			e := channel.New(0, 1500, linkAddr)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ipv4.ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, addr2, err)
			}

			for _, f := range test.fragments {
				pktSize := header.IPv4MinimumSize + len(f.payload)
				hdr := buffer.NewPrependable(pktSize)

				ip := header.IPv4(hdr.Prepend(pktSize))
				ip.Encode(&f.ipv4fields)
				// Encode sets this up correctly. If we want a different value for
				// testing then we need to overwrite the good value.
				if f.overrideIHL != 0 {
					ip.SetHeaderLength(uint8(f.overrideIHL))
				}
				copy(ip[header.IPv4MinimumSize:], f.payload)

				if f.autoChecksum {
					ip.SetChecksum(0)
					ip.SetChecksum(^ip.CalculateChecksum())
				}

				vv := hdr.View().ToVectorisedView()
				e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}))
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.wantMalformedIPPackets; got != want {
				t.Errorf("incorrect Stats.IP.MalformedPacketsReceived, got: %d, want: %d", got, want)
			}
			if got, want := s.Stats().IP.MalformedFragmentsReceived.Value(), test.wantMalformedFragments; got != want {
				t.Errorf("incorrect Stats.IP.MalformedFragmentsReceived, got: %d, want: %d", got, want)
			}
		})
	}
}

func TestFragmentReassemblyTimeout(t *testing.T) {
	const (
		nicID    = 1
		linkAddr = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		addr1    = "\x0a\x00\x00\x01"
		addr2    = "\x0a\x00\x00\x02"
		tos      = 0
		ident    = 1
		ttl      = 48
		protocol = 99
		data     = "TEST_FRAGMENT_REASSEMBLY_TIMEOUT"
	)

	type fragmentData struct {
		ipv4fields header.IPv4Fields
		payload    []byte
	}

	tests := []struct {
		name       string
		fragments  []fragmentData
		expectICMP bool
	}{
		{
			name: "first fragment only",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
		{
			name: "two first fragments",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:16],
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
		{
			name: "second fragment only",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    uint16(header.IPv4MinimumSize + len(data) - 16),
						ID:             ident,
						Flags:          0,
						FragmentOffset: 8,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[16:],
				},
			},
			expectICMP: false,
		},
		{
			name: "two fragments with a gap",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:8],
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    uint16(header.IPv4MinimumSize + len(data) - 16),
						ID:             ident,
						Flags:          0,
						FragmentOffset: 16,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[16:],
				},
			},
			expectICMP: true,
		},
		{
			name: "two fragments with a gap in reverse order",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    uint16(header.IPv4MinimumSize + len(data) - 16),
						ID:             ident,
						Flags:          0,
						FragmentOffset: 16,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[16:],
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:8],
				},
			},
			expectICMP: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{
					ipv4.NewProtocol,
				},
				Clock: clock,
			})
			e := channel.New(1, 1500, linkAddr)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ipv4.ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, addr2, err)
			}
			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv4EmptySubnet,
				NIC:         nicID,
			}})

			var firstFragmentSent buffer.View
			for _, f := range test.fragments {
				pktSize := header.IPv4MinimumSize
				hdr := buffer.NewPrependable(pktSize)

				ip := header.IPv4(hdr.Prepend(pktSize))
				ip.Encode(&f.ipv4fields)

				ip.SetChecksum(0)
				ip.SetChecksum(^ip.CalculateChecksum())

				vv := hdr.View().ToVectorisedView()
				vv.AppendView(f.payload)

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				})

				if firstFragmentSent == nil && ip.FragmentOffset() == 0 {
					firstFragmentSent = stack.PayloadSince(pkt.NetworkHeader())
				}

				e.InjectInbound(header.IPv4ProtocolNumber, pkt)
			}

			clock.Advance(ipv4.ReassembleTimeout)

			reply, ok := e.Read()
			if !test.expectICMP {
				if ok {
					t.Fatalf("unexpected ICMP error message received: %#v", reply)
				}
				return
			}
			if !ok {
				t.Fatal("expected ICMP error message missing")
			}
			if firstFragmentSent == nil {
				t.Fatalf("unexpected ICMP error message received: %#v", reply)
			}

			checker.IPv4(t, stack.PayloadSince(reply.Pkt.NetworkHeader()),
				checker.SrcAddr(addr2),
				checker.DstAddr(addr1),
				checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+firstFragmentSent.Size())),
				checker.IPv4HeaderLength(header.IPv4MinimumSize),
				checker.ICMPv4(
					checker.ICMPv4Type(header.ICMPv4TimeExceeded),
					checker.ICMPv4Code(header.ICMPv4ReassemblyTimeout),
					checker.ICMPv4Checksum(),
					checker.ICMPv4Payload([]byte(firstFragmentSent)),
				),
			)
		})
	}
}

// TestReceiveFragments feeds fragments in through the incoming packet path to
// test reassembly
func TestReceiveFragments(t *testing.T) {
	const (
		nicID = 1

		addr1 = "\x0c\xa8\x00\x01" // 192.168.0.1
		addr2 = "\x0c\xa8\x00\x02" // 192.168.0.2
		addr3 = "\x0c\xa8\x00\x03" // 192.168.0.3
	)

	// Build and return a UDP header containing payload.
	udpGen := func(payloadLen int, multiplier uint8, src, dst tcpip.Address) buffer.View {
		payload := buffer.NewView(payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = uint8(i) * multiplier
		}

		udpLength := header.UDPMinimumSize + len(payload)

		hdr := buffer.NewPrependable(udpLength)
		u := header.UDP(hdr.Prepend(udpLength))
		u.Encode(&header.UDPFields{
			SrcPort: 5555,
			DstPort: 80,
			Length:  uint16(udpLength),
		})
		copy(u.Payload(), payload)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLength))
		sum = header.Checksum(payload, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))
		return hdr.View()
	}

	// UDP header plus a payload of 0..256
	ipv4Payload1Addr1ToAddr2 := udpGen(256, 1, addr1, addr2)
	udpPayload1Addr1ToAddr2 := ipv4Payload1Addr1ToAddr2[header.UDPMinimumSize:]
	ipv4Payload1Addr3ToAddr2 := udpGen(256, 1, addr3, addr2)
	udpPayload1Addr3ToAddr2 := ipv4Payload1Addr3ToAddr2[header.UDPMinimumSize:]
	// UDP header plus a payload of 0..256 in increments of 2.
	ipv4Payload2Addr1ToAddr2 := udpGen(128, 2, addr1, addr2)
	udpPayload2Addr1ToAddr2 := ipv4Payload2Addr1ToAddr2[header.UDPMinimumSize:]
	// UDP header plus a payload of 0..256 in increments of 3.
	// Used to test cases where the fragment blocks are not a multiple of
	// the fragment block size of 8 (RFC 791 section 3.1 page 14).
	ipv4Payload3Addr1ToAddr2 := udpGen(127, 3, addr1, addr2)
	udpPayload3Addr1ToAddr2 := ipv4Payload3Addr1ToAddr2[header.UDPMinimumSize:]
	// Used to test the max reassembled payload length (65,535 octets).
	ipv4Payload4Addr1ToAddr2 := udpGen(header.UDPMaximumSize-header.UDPMinimumSize, 4, addr1, addr2)
	udpPayload4Addr1ToAddr2 := ipv4Payload4Addr1ToAddr2[header.UDPMinimumSize:]

	type fragmentData struct {
		srcAddr        tcpip.Address
		dstAddr        tcpip.Address
		id             uint16
		flags          uint8
		fragmentOffset uint16
		payload        buffer.View
	}

	tests := []struct {
		name             string
		fragments        []fragmentData
		expectedPayloads [][]byte
	}{
		{
			name: "No fragmentation",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "No fragmentation with size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "More fragments without payload",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Non-zero fragment offset without payload",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 8,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments out of order",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with last fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload3Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments with first fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2[:63],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 63,
					payload:        ipv4Payload3Addr1ToAddr2[63:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Second fragment has MoreFlags set",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with different IDs",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two interleaved fragmented packets",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload2Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload2Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload2Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets from different sources but with same ID",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr3,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr3ToAddr2[:32],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr3,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 32,
					payload:        ipv4Payload1Addr3ToAddr2[32:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload1Addr3ToAddr2},
		},
		{
			name: "Fragment without followup",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload4Addr1ToAddr2[:65512],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 65512,
					payload:        ipv4Payload4Addr1ToAddr2[65512:],
				},
			},
			expectedPayloads: [][]byte{udpPayload4Addr1ToAddr2},
		},
		{
			name: "Two fragments with MF flag reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload4Addr1ToAddr2[:65512],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 65512,
					payload:        ipv4Payload4Addr1ToAddr2[65512:],
				},
			},
			expectedPayloads: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Setup a stack and endpoint.
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			e := channel.New(0, 1280, tcpip.LinkAddress("\xf0\x00"))
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, header.IPv4ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, addr2, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, header.IPv4ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			// Prepare and send the fragments.
			for _, frag := range test.fragments {
				hdr := buffer.NewPrependable(header.IPv4MinimumSize)

				// Serialize IPv4 fixed header.
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength:    header.IPv4MinimumSize + uint16(len(frag.payload)),
					ID:             frag.id,
					Flags:          frag.flags,
					FragmentOffset: frag.fragmentOffset,
					TTL:            64,
					Protocol:       uint8(header.UDPProtocolNumber),
					SrcAddr:        frag.srcAddr,
					DstAddr:        frag.dstAddr,
				})
				ip.SetChecksum(^ip.CalculateChecksum())

				vv := hdr.View().ToVectorisedView()
				vv.AppendView(frag.payload)

				e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}))
			}

			if got, want := s.Stats().UDP.PacketsReceived.Value(), uint64(len(test.expectedPayloads)); got != want {
				t.Errorf("got UDP Rx Packets = %d, want = %d", got, want)
			}

			for i, expectedPayload := range test.expectedPayloads {
				var buf bytes.Buffer
				result, err := ep.Read(&buf, tcpip.ReadOptions{})
				if err != nil {
					t.Fatalf("(i=%d) Read: %s", i, err)
				}
				if diff := cmp.Diff(tcpip.ReadResult{
					Count: len(expectedPayload),
					Total: len(expectedPayload),
				}, result, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
					t.Errorf("(i=%d) ep.Read: unexpected result (-want +got):\n%s", i, diff)
				}
				if diff := cmp.Diff(expectedPayload, buf.Bytes()); diff != "" {
					t.Errorf("(i=%d) got UDP payload mismatch (-want +got):\n%s", i, diff)
				}
			}

			if res, err := ep.Read(ioutil.Discard, tcpip.ReadOptions{}); err != tcpip.ErrWouldBlock {
				t.Fatalf("(last) got Read = (%v, %v), want = (_, %s)", res, err, tcpip.ErrWouldBlock)
			}
		})
	}
}

func TestWriteStats(t *testing.T) {
	const nPackets = 3

	tests := []struct {
		name          string
		setup         func(*testing.T, *stack.Stack)
		allowPackets  int
		expectSent    int
		expectDropped int
		expectWritten int
	}{
		{
			name: "Accept all",
			// No setup needed, tables accept everything by default.
			setup:         func(*testing.T, *stack.Stack) {},
			allowPackets:  math.MaxInt32,
			expectSent:    nPackets,
			expectDropped: 0,
			expectWritten: nPackets,
		}, {
			name: "Accept all with error",
			// No setup needed, tables accept everything by default.
			setup:         func(*testing.T, *stack.Stack) {},
			allowPackets:  nPackets - 1,
			expectSent:    nPackets - 1,
			expectDropped: 0,
			expectWritten: nPackets - 1,
		}, {
			name: "Drop all",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule.
				t.Helper()
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */); err != nil {
					t.Fatalf("failed to replace table: %s", err)
				}
			},
			allowPackets:  math.MaxInt32,
			expectSent:    0,
			expectDropped: nPackets,
			expectWritten: nPackets,
		}, {
			name: "Drop some",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule that matches only 1
				// of the 3 packets.
				t.Helper()
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */); err != nil {
					t.Fatalf("failed to replace table: %s", err)
				}
			},
			allowPackets:  math.MaxInt32,
			expectSent:    nPackets - 1,
			expectDropped: 1,
			expectWritten: nPackets,
		},
	}

	// Parameterize the tests to run with both WritePacket and WritePackets.
	writers := []struct {
		name         string
		writePackets func(*stack.Route, stack.PacketBufferList) (int, *tcpip.Error)
	}{
		{
			name: "WritePacket",
			writePackets: func(rt *stack.Route, pkts stack.PacketBufferList) (int, *tcpip.Error) {
				nWritten := 0
				for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
					if err := rt.WritePacket(nil, stack.NetworkHeaderParams{}, pkt); err != nil {
						return nWritten, err
					}
					nWritten++
				}
				return nWritten, nil
			},
		}, {
			name: "WritePackets",
			writePackets: func(rt *stack.Route, pkts stack.PacketBufferList) (int, *tcpip.Error) {
				return rt.WritePackets(nil, pkts, stack.NetworkHeaderParams{})
			},
		},
	}

	for _, writer := range writers {
		t.Run(writer.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					ep := testutil.NewMockLinkEndpoint(header.IPv4MinimumMTU, tcpip.ErrInvalidEndpointState, test.allowPackets)
					rt := buildRoute(t, ep)

					var pkts stack.PacketBufferList
					for i := 0; i < nPackets; i++ {
						pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
							ReserveHeaderBytes: header.UDPMinimumSize + int(rt.MaxHeaderLength()),
							Data:               buffer.NewView(0).ToVectorisedView(),
						})
						pkt.TransportHeader().Push(header.UDPMinimumSize)
						pkts.PushBack(pkt)
					}

					test.setup(t, rt.Stack())

					nWritten, _ := writer.writePackets(rt, pkts)

					if got := int(rt.Stats().IP.PacketsSent.Value()); got != test.expectSent {
						t.Errorf("sent %d packets, but expected to send %d", got, test.expectSent)
					}
					if got := int(rt.Stats().IP.IPTablesOutputDropped.Value()); got != test.expectDropped {
						t.Errorf("dropped %d packets, but expected to drop %d", got, test.expectDropped)
					}
					if nWritten != test.expectWritten {
						t.Errorf("wrote %d packets, but expected WritePackets to return %d", nWritten, test.expectWritten)
					}
				})
			}
		})
	}
}

func buildRoute(t *testing.T, ep stack.LinkEndpoint) *stack.Route {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC(1, _) failed: %s", err)
	}
	const (
		src = "\x10\x00\x00\x01"
		dst = "\x10\x00\x00\x02"
	)
	if err := s.AddAddress(1, ipv4.ProtocolNumber, src); err != nil {
		t.Fatalf("AddAddress(1, %d, %s) failed: %s", ipv4.ProtocolNumber, src, err)
	}
	{
		mask := tcpip.AddressMask(header.IPv4Broadcast)
		subnet, err := tcpip.NewSubnet(dst, mask)
		if err != nil {
			t.Fatalf("NewSubnet(%s, %s) failed: %v", dst, mask, err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	rt, err := s.FindRoute(1, src, dst, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %s, %s, %d, false) = %s", src, dst, ipv4.ProtocolNumber, err)
	}
	return rt
}

// limitedMatcher is an iptables matcher that matches after a certain number of
// packets are checked against it.
type limitedMatcher struct {
	limit int
}

// Name implements Matcher.Name.
func (*limitedMatcher) Name() string {
	return "limitedMatcher"
}

// Match implements Matcher.Match.
func (lm *limitedMatcher) Match(stack.Hook, *stack.PacketBuffer, string) (bool, bool) {
	if lm.limit == 0 {
		return true, false
	}
	lm.limit--
	return false, false
}

func TestPacketQueing(t *testing.T) {
	const nicID = 1

	var (
		host1NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
		host2NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")

		host1IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
				PrefixLen: 24,
			},
		}
		host2IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
				PrefixLen: 8,
			},
		}
	)

	tests := []struct {
		name      string
		rxPkt     func(*channel.Endpoint)
		checkResp func(*testing.T, *channel.Endpoint)
	}{
		{
			name: "ICMP Error",
			rxPkt: func(e *channel.Endpoint) {
				hdr := buffer.NewPrependable(header.IPv4MinimumSize + header.UDPMinimumSize)
				u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
				u.Encode(&header.UDPFields{
					SrcPort: 5555,
					DstPort: 80,
					Length:  header.UDPMinimumSize,
				})
				sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, host2IPv4Addr.AddressWithPrefix.Address, host1IPv4Addr.AddressWithPrefix.Address, header.UDPMinimumSize)
				sum = header.Checksum(header.UDP([]byte{}), sum)
				u.SetChecksum(^u.CalculateChecksum(sum))
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
					TTL:         ipv4.DefaultTTL,
					Protocol:    uint8(udp.ProtocolNumber),
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				e.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != header.IPv4ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, header.IPv4ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, host2NICLinkAddr)
				}
				checker.IPv4(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4DstUnreachable),
						checker.ICMPv4Code(header.ICMPv4PortUnreachable)))
			},
		},

		{
			name: "Ping",
			rxPkt: func(e *channel.Endpoint) {
				totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
				hdr := buffer.NewPrependable(totalLen)
				pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
				pkt.SetType(header.ICMPv4Echo)
				pkt.SetCode(0)
				pkt.SetChecksum(0)
				pkt.SetChecksum(^header.Checksum(pkt, 0))
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength: uint16(totalLen),
					Protocol:    uint8(icmp.ProtocolNumber4),
					TTL:         ipv4.DefaultTTL,
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != header.IPv4ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, header.IPv4ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, host2NICLinkAddr)
				}
				checker.IPv4(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4EchoReply),
						checker.ICMPv4Code(header.ICMPv4UnusedCode)))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := channel.New(1, defaultMTU, host1NICLinkAddr)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})

			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddProtocolAddress(nicID, host1IPv4Addr); err != nil {
				t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID, host1IPv4Addr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         nicID,
				},
			})

			// Receive a packet to trigger link resolution before a response is sent.
			test.rxPkt(e)

			// Wait for a ARP request since link address resolution should be
			// performed.
			{
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != arp.ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, arp.ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != header.EthernetBroadcastAddress {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, header.EthernetBroadcastAddress)
				}
				rep := header.ARP(p.Pkt.NetworkHeader().View())
				if got := rep.Op(); got != header.ARPRequest {
					t.Errorf("got Op() = %d, want = %d", got, header.ARPRequest)
				}
				if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != host1NICLinkAddr {
					t.Errorf("got HardwareAddressSender = %s, want = %s", got, host1NICLinkAddr)
				}
				if got := tcpip.Address(rep.ProtocolAddressSender()); got != host1IPv4Addr.AddressWithPrefix.Address {
					t.Errorf("got ProtocolAddressSender = %s, want = %s", got, host1IPv4Addr.AddressWithPrefix.Address)
				}
				if got := tcpip.Address(rep.ProtocolAddressTarget()); got != host2IPv4Addr.AddressWithPrefix.Address {
					t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, host2IPv4Addr.AddressWithPrefix.Address)
				}
			}

			// Send an ARP reply to complete link address resolution.
			{
				hdr := buffer.View(make([]byte, header.ARPSize))
				packet := header.ARP(hdr)
				packet.SetIPv4OverEthernet()
				packet.SetOp(header.ARPReply)
				copy(packet.HardwareAddressSender(), host2NICLinkAddr)
				copy(packet.ProtocolAddressSender(), host2IPv4Addr.AddressWithPrefix.Address)
				copy(packet.HardwareAddressTarget(), host1NICLinkAddr)
				copy(packet.ProtocolAddressTarget(), host1IPv4Addr.AddressWithPrefix.Address)
				e.InjectInbound(arp.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.ToVectorisedView(),
				}))
			}

			// Expect the response now that the link address has resolved.
			test.checkResp(t, e)

			// Since link resolution was already performed, it shouldn't be performed
			// again.
			test.rxPkt(e)
			test.checkResp(t, e)
		})
	}
}
