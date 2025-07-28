// Copyright 2024 The gVisor Authors.
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

package nftables

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Table Constants.
const (
	arbitraryTargetChain         string              = "target_chain"
	arbitraryHook                stack.NFHook        = stack.NFPrerouting
	arbitraryFamily              stack.AddressFamily = stack.Inet
	arbitraryReservedHeaderBytes int                 = 16
)

var (
	arbitraryPriority Priority = func() Priority {
		priority, err := NewStandardPriority("filter", arbitraryFamily, arbitraryHook)
		if err != nil {
			panic(fmt.Sprintf("unexpected error for NewStandardPriority: %v", err))
		}
		return priority
	}()

	arbitraryInfoPolicyAccept *BaseChainInfo = &BaseChainInfo{
		BcType:   BaseChainTypeFilter,
		Hook:     arbitraryHook,
		Priority: arbitraryPriority,
	}
)

// Packet Constants.
const (
	tcpTransportProtocol = header.TCPProtocolNumber

	arbitraryHeaderID   = 3
	arbitraryTimeToLive = 64

	arbitraryPort    = 12345
	arbitraryPort2   = 80
	tcpSeqNum        = 32
	tcpAckNum        = 165
	tcpWinSize       = 65535
	tcpUrgentPointer = 0

	arbitraryNonZeroFragmentOffset = 16

	// TODO(b/345684870): Use constants defined in the pkg/tcpip/header package.
	// Ethernet Offsets and Lengths.
	ethDstAddrOffset = 0
	ethDstAddrLen    = 6
	ethSrcAddrOffset = 6
	ethSrcAddrLen    = 6
	ethTypeOffset    = 12
	ethTypeLen       = 2

	// IPv4 Offsets and Lengths.
	ipv4LengthOffset   = 2
	ipv4LengthLen      = 2
	ipv4IDOffset       = 4
	ipv4IDLen          = 2
	ipv4FragOffOffset  = 6
	ipv4FragOffLen     = 2
	ipv4TTLOffset      = 8
	ipv4TTLLen         = 1
	ipv4ProtocolOffset = 9
	ipv4ProtocolLen    = 1
	ipv4ChecksumOffset = 10
	ipv4ChecksumLen    = 2
	ipv4SrcAddrOffset  = 12
	ipv4SrcAddrLen     = 4
	ipv4DstAddrOffset  = 16
	ipv4DstAddrLen     = 4

	// IPv6 Offsets and Lengths.
	ipv6LengthOffset   = 4
	ipv6LengthLen      = 2
	ipv6NextHdrOffset  = 6
	ipv6NextHdrLen     = 1
	ipv6HopLimitOffset = 7
	ipv6HopLimitLen    = 1
	ipv6SrcAddrOffset  = 8
	ipv6SrcAddrLen     = 16
	ipv6DstAddrOffset  = 24
	ipv6DstAddrLen     = 16

	// TCP Offsets and Lengths.
	tcpSrcPortOffset  = 0
	tcpSrcPortLen     = 2
	tcpDstPortOffset  = 2
	tcpDstPortLen     = 2
	tcpSeqNumOffset   = 4
	tcpSeqNumLen      = 4
	tcpAckNumOffset   = 8
	tcpAckNumLen      = 4
	tcpWindowOffset   = 14
	tcpWindowLen      = 2
	tcpChecksumOffset = 16
	tcpChecksumLen    = 2
	tcpUrgPtrOffset   = 18
	tcpUrgPtrLen      = 2

	// Arbitrary Socket IDs
	arbitrarySKUID = 0x020304
	arbitrarySKGID = 45668

	// Arbitrary Packet Type
	arbitraryPktType = tcpip.PacketOutgoing
)

var (
	arbitraryLinkAddr     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	arbitraryLinkAddr2    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	arbitraryLinkAddrB    = [6]byte{0x02, 0x02, 0x03, 0x04, 0x05, 0x06}
	arbitraryLinkAddrB2   = [6]byte{0x02, 0x02, 0x03, 0x04, 0x05, 0x07}
	arbitraryEthernetType = header.IPv4ProtocolNumber

	arbitraryIPv4AddrB  = [4]byte{192, 168, 1, 1}
	arbitraryIPv4AddrB2 = [4]byte{192, 168, 1, 9}
	ipv4MinTotalLength  = header.IPv4MinimumSize

	arbitraryIPv6AddrB   = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa}
	arbitraryIPv6AddrB2  = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbb}
	ipv6MinPayloadLength = 0

	// Note: these are functions to make sure they are not modified by tests and
	// so each tests gets a new value.
	arbitraryEthernetFields = func() *header.EthernetFields {
		return &header.EthernetFields{
			SrcAddr: arbitraryLinkAddr,
			DstAddr: arbitraryLinkAddr2,
			Type:    arbitraryEthernetType,
		}
	}

	arbitraryIPv4Fields = func() *header.IPv4Fields {
		return &header.IPv4Fields{
			TOS:            0,
			TotalLength:    uint16(ipv4MinTotalLength),
			ID:             arbitraryHeaderID,
			FragmentOffset: 0,
			TTL:            arbitraryTimeToLive,
			Protocol:       uint8(tcpTransportProtocol),
			Checksum:       0,
			SrcAddr:        tcpip.AddrFrom4(arbitraryIPv4AddrB),
			DstAddr:        tcpip.AddrFrom4(arbitraryIPv4AddrB2),
			Options:        nil,
		}
	}

	fragmentedIPv4Fields = func() *header.IPv4Fields {
		fields := arbitraryIPv4Fields()
		fields.FragmentOffset = arbitraryNonZeroFragmentOffset
		return fields
	}

	arbitraryIPv6Fields = func() *header.IPv6Fields {
		return &header.IPv6Fields{
			TrafficClass:      0,
			FlowLabel:         0,
			PayloadLength:     uint16(ipv6MinPayloadLength),
			TransportProtocol: tcpTransportProtocol,
			HopLimit:          arbitraryTimeToLive,
			SrcAddr:           tcpip.AddrFrom16(arbitraryIPv6AddrB),
			DstAddr:           tcpip.AddrFrom16(arbitraryIPv6AddrB2),
		}
	}

	arbitraryTCPFields = func() *header.TCPFields {
		return &header.TCPFields{
			SrcPort:       uint16(arbitraryPort),
			DstPort:       uint16(arbitraryPort2),
			SeqNum:        uint32(tcpSeqNum),
			AckNum:        uint32(tcpAckNum),
			DataOffset:    header.TCPMinimumSize,
			WindowSize:    uint16(tcpWinSize),
			Checksum:      0,
			UrgentPointer: uint16(tcpUrgentPointer),
		}
	}
)

// makeArbitraryPacket creates an arbitrary packet for testing.
func makeArbitraryPacket(reserved int) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserved,
		Payload:            buffer.MakeWithData([]byte{0, 2, 4, 8, 16, 32, 64, 128}),
	})
}

// makeEthernetPacket creates a packet with an Ethernet header.
func makeEthernetPacket(reserved int, ethFields *header.EthernetFields) *stack.PacketBuffer {
	eth := make([]byte, header.EthernetMinimumSize)
	header.Ethernet(eth).Encode(ethFields)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserved,
		Payload:            buffer.MakeWithData(eth),
	})
	pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return pkt
}

// makeIPv4Packet creates a packet with an IPv4 header.
func makeIPv4Packet(reserved int, ipv4Fields *header.IPv4Fields) *stack.PacketBuffer {
	// Creates a new PacketBuffer with enough space for the IPv4 header.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserved,
	})

	// Prepends the IPv4 header to the packet buffer.
	ipv4Hdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))

	// Sets the packet type.
	pkt.PktType = arbitraryPktType

	// Initializes the IPv4 header with fields.
	ipv4Hdr.Encode(ipv4Fields)

	// Calculates and sets the checksum.
	ipv4Hdr.SetChecksum(^ipv4Hdr.CalculateChecksum())

	// Sets the network protocol number.
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber

	return pkt
}

// makeIPv6Packet creates a packet with an IPv6 header.
func makeIPv6Packet(reserved int, ipv6Fields *header.IPv6Fields) *stack.PacketBuffer {
	// Creates a new PacketBuffer with enough space for the IPv4 header.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserved,
	})

	// Prepends the IPv6 header to the packet buffer.
	ipv6Hdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))

	// Sets the packet type.
	pkt.PktType = arbitraryPktType

	// Initializes the IPv6 header with fields.
	ipv6Hdr.Encode(ipv6Fields)

	// No checksum for IPv6 (relies on L4 checksum if extra security is needed).

	// Sets the network protocol number.
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber

	return pkt
}

// addTCPHeader adds a TCP header to a packet and returns the header.
// Note: this does not compute the checksum.
func addTCPHeader(pkt *stack.PacketBuffer, tcpFields *header.TCPFields) header.TCP {
	// Prepends the TCP header to the packet buffer.
	tcpHdr := header.TCP(pkt.TransportHeader().Push(int(tcpFields.DataOffset)))

	// Initializes the TCP header with fields.
	tcpHdr.Encode(tcpFields)

	// Sets the transport protocol number.
	pkt.TransportProtocolNumber = header.TCPProtocolNumber

	return tcpHdr
}

// makeIPv4TCPPacket creates a packet with an IPv4 and TCP header.
func makeIPv4TCPPacket(reserved int, ipv4Fields *header.IPv4Fields, tcpFields *header.TCPFields) *stack.PacketBuffer {
	// Makes a packet with the L3 IPv4 header (this sets the checksum).
	pkt := makeIPv4Packet(reserved, ipv4Fields)

	// Adds the L4 TCP header.
	tcpHdr := addTCPHeader(pkt, tcpFields)

	// Calculates the TCP checksum using the pseudo-header and sets it in the TCP header.
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(
		tcpip.TransportProtocolNumber(ipv4Fields.Protocol),
		ipv4Fields.SrcAddr,
		ipv4Fields.DstAddr,
		uint16(tcpFields.DataOffset),
	)))

	return pkt
}

// makeIPv6TCPPacket creates a packet with an IPv6 and TCP header.
func makeIPv6TCPPacket(reserved int, ipv6Fields *header.IPv6Fields, tcpFields *header.TCPFields) *stack.PacketBuffer {
	// Makes a packet with the L3 IPv6 header (this sets the checksum).
	pkt := makeIPv6Packet(reserved, ipv6Fields)

	// Adds the L4 TCP header.
	tcpHdr := addTCPHeader(pkt, tcpFields)

	// Calculates the TCP checksum using the pseudo-header and sets it in the TCP header.
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(
		// Next header is supposed to be in pseudo-header calculation for IPv6
		// transport protocol checksum, not the transport protocol number according
		// to RFC 2460 (https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1).
		header.IPv6(pkt.NetworkHeader().Slice()).TransportProtocol(),
		ipv6Fields.SrcAddr,
		ipv6Fields.DstAddr,
		uint16(ipv6Fields.PayloadLength),
	)))

	return pkt
}

// TestUnsupportedAddressFamily tests that an empty NFTables object returns an
// error when evaluating a packet for an unsupported address family.
func TestUnsupportedAddressFamily(t *testing.T) {
	// Makes arbitrary packet for comparison (to check for no changes).
	cmpPkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
	nf := newNFTablesStd()
	for _, unsupportedFamily := range []stack.AddressFamily{stack.AddressFamily(stack.NumAFs), stack.AddressFamily(-1)} {
		// Note: the Prerouting hook is arbitrary (any hook would work).
		pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
		v, err := nf.EvaluateHook(unsupportedFamily, arbitraryHook, pkt)
		if err == nil {
			t.Fatalf("expecting error for EvaluateHook with unsupported address family %d; got %v verdict, %s packet, and error %v",
				int(unsupportedFamily),
				v, packetResultString(cmpPkt, pkt), err)
		}
	}
}

// TestAcceptAll tests that an empty NFTables object accepts all packets for
// supported hooks and errors for unsupported hooks for all address families
// when evaluating packets at the hook-level.
func TestAcceptAllForSupportedHooks(t *testing.T) {
	// Makes arbitrary packet for comparison (to check for no changes).
	cmpPkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
	for _, family := range []stack.AddressFamily{stack.IP, stack.IP6, stack.Inet, stack.Arp, stack.Bridge, stack.Netdev} {
		t.Run(family.String()+" address family", func(t *testing.T) {
			nf := newNFTablesStd()
			for _, hook := range []stack.NFHook{stack.NFPrerouting, stack.NFInput, stack.NFForward, stack.NFOutput, stack.NFPostrouting, stack.NFIngress, stack.NFEgress} {
				pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
				v, err := nf.EvaluateHook(family, hook, pkt)

				supported := false
				for _, h := range supportedHooks[family] {
					if h == hook {
						supported = true
						break
					}
				}

				if supported {
					if err != nil || v.Code != VC(linux.NF_ACCEPT) {
						t.Fatalf("expecting accept verdict for EvaluateHook with supported hook %v for family %v; got %v verdict, %s packet, and error %v",
							hook, family,
							v, packetResultString(cmpPkt, pkt), err)
					}
				} else {
					if err == nil {
						t.Fatalf("expecting error for EvaluateHook with unsupported hook %v for family %v; got %v verdict, %s packet, and error %v",
							hook, family,
							v, packetResultString(cmpPkt, pkt), err)
					}
				}
			}
		})
	}
}

// TestEvaluateImmediateVerdict tests that the Immediate operation correctly sets the
// register value and behaves as expected during evaluation.
func TestEvaluateImmediateVerdict(t *testing.T) {
	for _, test := range []struct {
		tname    string
		baseOp1  operation // will be nil if unused
		baseOp2  operation // will be nil if unused
		targetOp operation // will be nil if unused
		verdict  stack.NFVerdict
	}{
		{
			tname:   "no operations",
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "immediately accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "immediately drop",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "immediately continue with base chain policy accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "immediately return with base chain policy accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_RETURN)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:    "immediately jump to target chain that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:    "immediately jump to target chain that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:    "immediately jump to target chain that continues with second rule that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:    "immediately jump to target chain that continues with second rule that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:    "immediately goto to target chain that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:    "immediately goto to target chain that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:    "immediately goto to target chain that continues with second rule that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:    "immediately goto to target chain that continues with second rule that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict:  stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "add data to register then accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG32_13, newBytesData([]byte{0, 1, 2, 3})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "add data to register then drop",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG32_15, newBytesData([]byte{0, 1, 2, 3})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "add data to register then continue",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0, 1, 2, 3})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "multiple accepts",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "multiple drops",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "immediately accept then drop",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "immediately drop then accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "immediate load register",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a base chain (for 2 rules) and another
			// target chain (for 1 rule).
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			tc, err := tab.AddChain(arbitraryTargetChain, nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}

			// Adds testing rules and operations.
			if test.baseOp1 != nil {
				rule1 := &Rule{}
				rule1.addOperation(test.baseOp1)
				if err := bc.RegisterRule(rule1, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule for the first operation: %v", err)
				}
			}
			if test.baseOp2 != nil {
				rule2 := &Rule{}
				rule2.addOperation(test.baseOp2)
				if err := bc.RegisterRule(rule2, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule for the second operation: %v", err)
				}
			}
			if test.targetOp != nil {
				ruleTarget := &Rule{}
				ruleTarget.addOperation(test.targetOp)
				if err := tc.RegisterRule(ruleTarget, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule for the target operation: %v", err)
				}
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)

			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}
			if v.Code != test.verdict.Code {
				t.Fatalf("expected verdict %v, got %v", test.verdict, v)
			}
		})
	}
}

// TestEvaluateImmediateVerdict tests that the Immediate operation correctly
// loads bytes data of all lengths into all supported registers.
func TestEvaluateImmediateBytesData(t *testing.T) {
	bytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	for blen := 1; blen <= len(bytes); blen++ {
		for _, registerSize := range []int{linux.NFT_REG32_SIZE, linux.NFT_REG_SIZE} {
			if blen > registerSize {
				continue
			}
			tname := fmt.Sprintf("immediately load %d bytes into %d-byte registers", blen, registerSize)
			t.Run(tname, func(t *testing.T) {
				// Sets up an NFTables object with a base chain with policy accept.
				nf := newNFTablesStd()
				tab, err := nf.AddTable(arbitraryFamily, "test", false)
				if err != nil {
					t.Fatalf("unexpected error for AddTable: %v", err)
				}
				bc, err := tab.AddChain("base_chain", nil, "test chain", false)
				if err != nil {
					t.Fatalf("unexpected error for AddChain: %v", err)
				}
				bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)

				// Adds a rule and immediate operation per register of registerSize.
				switch registerSize {
				case linux.NFT_REG32_SIZE:
					for reg := linux.NFT_REG32_00; reg <= linux.NFT_REG32_15; reg++ {
						rule := &Rule{}
						rule.addOperation(mustCreateImmediate(t, uint8(reg), newBytesData(bytes[:blen])))
						if err := bc.RegisterRule(rule, -1); err != nil {
							t.Fatalf("unexpected error for RegisterRule for rule %d: %v", reg-linux.NFT_REG32_00, err)
						}
					}
				case linux.NFT_REG_SIZE:
					for reg := linux.NFT_REG_1; reg <= linux.NFT_REG_4; reg++ {
						rule := &Rule{}
						rule.addOperation(mustCreateImmediate(t, uint8(reg), newBytesData(bytes[:blen])))
						if err := bc.RegisterRule(rule, -1); err != nil {
							t.Fatalf("unexpected error for RegisterRule for rule %d: %v", reg-linux.NFT_REG_1, err)
						}
					}
				}
				// Runs evaluation and checks for default policy verdict accept
				pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
				v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
				if err != nil {
					t.Fatalf("unexpected error for EvaluateHook: %v", err)
				}
				if v.Code != linux.NF_ACCEPT {
					t.Fatalf("expected default policy verdict accept, got %v", v)
				}
			})
		}
	}
}

// TestEvaluateComparison tests that the Comparison operation correctly compares
// the data in the source register to the given data.
// Note: Relies on expected behavior of the Immediate operation.
func TestEvaluateComparison(t *testing.T) {
	for _, test := range []struct {
		tname string
		op1   operation // will be nil if unused
		op2   operation // will be nil if unused
		res   bool      // should be true if we reach end of the rule (no breaks)
	}{
		// 4-byte data comparisons, alternates between 4-byte and 16-byte registers.
		{
			tname: "compare register == 4-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register == 4-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_11, newBytesData([]byte{1, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_11, linux.NFT_CMP_EQ, []byte{0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register != 4-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_03, newBytesData([]byte{1, 7, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_03, linux.NFT_CMP_NEQ, []byte{1, 98, 0, 56}),
			res:   true,
		},
		{
			tname: "compare register != 4-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{1, 98, 0, 56})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_NEQ, []byte{1, 98, 0, 56}),
			res:   false,
		},
		{
			tname: "compare register < 4-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{29, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LT, []byte{100, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register < 4-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_04, newBytesData([]byte{100, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_04, linux.NFT_CMP_LT, []byte{100, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register < 4-byte data, false gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_14, newBytesData([]byte{200, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_14, linux.NFT_CMP_LT, []byte{100, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register > 4-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_15, newBytesData([]byte{29, 76, 230, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_15, linux.NFT_CMP_GT, []byte{0, 0, 0, 1}),
			res:   true,
		},
		{
			tname: "compare register > 4-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_07, newBytesData([]byte{29, 76, 230, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_07, linux.NFT_CMP_GT, []byte{29, 76, 230, 0}),
			res:   false,
		},
		{
			tname: "compare register > 4-byte data, false lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_05, newBytesData([]byte{28, 76, 230, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_05, linux.NFT_CMP_GT, []byte{29, 76, 230, 0}),
			res:   false,
		},
		{
			tname: "compare register <= 4-byte data, true lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{29, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_LTE, []byte{100, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register <= 4-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_09, newBytesData([]byte{100, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_09, linux.NFT_CMP_LTE, []byte{100, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register <= 4-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_06, newBytesData([]byte{200, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_06, linux.NFT_CMP_LTE, []byte{100, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register >= 4-byte data, true gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_12, newBytesData([]byte{29, 76, 230, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG32_12, linux.NFT_CMP_GTE, []byte{0, 0, 0, 1}),
			res:   true,
		},
		{
			tname: "compare register >= 4-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{29, 76, 230, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_GTE, []byte{29, 76, 230, 0}),
			res:   true,
		},
		{
			tname: "compare register >= 4-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{28, 76, 230, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{29, 76, 230, 0}),
			res:   false,
		},
		// 8-byte data comparisons.
		{
			tname: "compare register == 8-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register == 8-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{1, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register != 8-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{1, 7, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_NEQ, []byte{1, 98, 0, 56, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register != 8-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{1, 98, 0, 56, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_NEQ, []byte{1, 98, 0, 56, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register < 8-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{29, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LT, []byte{100, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register < 8-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{100, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_LT, []byte{100, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register < 8-byte data, false gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{200, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{100, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register > 8-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{29, 76, 230, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GT, []byte{0, 0, 0, 1, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register > 8-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{29, 76, 230, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_GT, []byte{29, 76, 230, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register > 8-byte data, false lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{28, 76, 230, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, []byte{29, 76, 230, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register <= 8-byte data, true lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{29, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LTE, []byte{100, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register <= 8-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{100, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, []byte{100, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register <= 8-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{200, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LTE, []byte{100, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register >= 8-byte data, true gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{30, 0, 0, 1, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GTE, []byte{29, 76, 230, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register >= 8-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{29, 76, 230, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{29, 76, 230, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register >= 8-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{28, 76, 230, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GTE, []byte{29, 76, 230, 0, 0, 0, 0, 0}),
			res:   false,
		},
		// 12-byte data comparisons.
		{
			tname: "compare register == 12-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register == 12-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare register != 12-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_NEQ, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}),
			res:   true,
		},
		{
			tname: "compare register != 12-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_NEQ, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}),
			res:   false,
		},
		{
			tname: "compare register < 12-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0x0a, 0x00, 0x01, 0x1f, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   true,
		},
		{
			tname: "compare register < 12-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_LT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   false,
		},
		{
			tname: "compare register < 12-byte data, false gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x0a, 0x00, 0x01, 0x21, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   false,
		},
		{
			tname: "compare register > 12-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x0a, 0x00, 0x01, 0x21, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   true,
		},
		{
			tname: "compare register > 12-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_GT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   false,
		},
		{
			tname: "compare register > 12-byte data, false lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0x0a, 0x00, 0x01, 0x1f, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   false,
		},
		{
			tname: "compare register <= 12-byte data, true lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   true,
		},
		{
			tname: "compare register <= 12-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   true,
		},
		{
			tname: "compare register <= 12-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0xaa, 0xaa, 0xaa, 0x20, 0xaa, 0xaa, 0xaa, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   false,
		},
		{
			tname: "compare register >= 12-byte data, true gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0xaa, 0xaa, 0xaa, 0x20, 0xaa, 0xaa, 0xaa, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   true,
		},
		{
			tname: "compare register >= 12-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56}),
			res:   true,
		},
		{
			tname: "compare register >= 12-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x0a, 0x00, 0x01, 0x19, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00}),
			res:   false,
		},
		// 16-byte data comparisons.
		{
			tname: "compare register == 16-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare register == 16-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			res:   false,
		},
		{
			tname: "compare register != 16-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_NEQ, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
			res:   true,
		},
		{
			tname: "compare register != 16-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_NEQ, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
			res:   false,
		},
		{
			tname: "compare register < 16-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0x0a, 0x00, 0x01, 0x1f, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0xaa})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   true,
		},
		{
			tname: "compare register < 16-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_LT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   false,
		},
		{
			tname: "compare register < 16-byte data, false gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x0a, 0x00, 0x01, 0x21, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0xaa})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   false,
		},
		{
			tname: "compare register > 16-byte data, true",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x0a, 0x00, 0x01, 0x21, 0xaa, 0xaa, 0xaa, 0xaa, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GT, []byte{0x0a, 0x00, 0x01, 0x20, 0xcc, 0xcc, 0xcc, 0xcc, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   true,
		},
		{
			tname: "compare register > 16-byte data, false eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_GT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   false,
		},
		{
			tname: "compare register > 16-byte data, false lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0x0a, 0x00, 0x01, 0x1f, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x90})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   false,
		},
		{
			tname: "compare register <= 16-byte data, true lt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x86})),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   true,
		},
		{
			tname: "compare register <= 16-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
			op2:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_LTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   true,
		},
		{
			tname: "compare register <= 16-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0xaa, 0x00, 0x0b, 0x13, 0x6a, 0x88})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   false,
		},
		{
			tname: "compare register >= 16-byte data, true gt",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0xaa, 0xaa, 0xaa, 0x20, 0xaa, 0xaa, 0xaa, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   true,
		},
		{
			tname: "compare register >= 16-byte data, true eq",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90})),
			op2:   mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90}),
			res:   true,
		},
		{
			tname: "compare register >= 16-byte data, false",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0a, 0x13, 0x6a, 0x85})),
			op2:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GTE, []byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87}),
			res:   false,
		},
		// Empty register comparisons.
		{
			tname: "compare empty 4-byte register, true",
			op1:   mustCreateComparison(t, linux.NFT_REG32_10, linux.NFT_CMP_EQ, []byte{0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare empty 4-byte register, false",
			op1:   mustCreateComparison(t, linux.NFT_REG32_11, linux.NFT_CMP_EQ, []byte{1, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare empty 8-byte register, true",
			op1:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_NEQ, []byte{1, 1, 1, 1, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare empty 8-byte register, false",
			op1:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GT, []byte{1, 1, 1, 1, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare empty 12-byte register, true",
			op1:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LTE, []byte{1, 1, 1, 1, 0, 0, 0, 0, 8, 9, 10, 11}),
			res:   true,
		},
		{
			tname: "compare empty 12-byte register, false",
			op1:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_NEQ, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "compare empty 16-byte register, true",
			op1:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_LT, []byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "compare empty 16-byte register, false",
			op1:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_GTE, []byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Add an operation that drops. This is what the final verdict should be
			// if all the comparisons are true (res = true).
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}
			// If all comparisons are true, the packet will get to the end of the rule
			// and the last operation above will set the final verdict to oppose the
			// base chain policy. If any comparison is false, the comparison operation
			// will break from the rule and the final verdict will default to the base
			// chain policy.
			if test.res {
				if v.Code != VC(linux.NF_DROP) {
					t.Fatalf("expected verdict Drop for %t result, got %v", test.res, v)
				}
			} else {
				if v.Code != VC(linux.NF_ACCEPT) {
					t.Fatalf("expected base chain policy verdict Accept for %t result, got %v", test.res, v)
				}
			}
		})
	}
}

// TestEvaluateRanged tests that the Ranged operation correctly checks that the
// the data in the source register is within the specified inclusive range.
// Note: Relies on expected behavior of the Immediate operation.
func TestEvaluateRanged(t *testing.T) {
	for _, test := range []struct {
		tname string
		op1   operation // Immediate operation that sets the source register.
		op2   operation // Ranged operation to test.
		res   bool      // should be true if we reach end of the rule (no breaks)
	}{
		// 4-byte ranges, alternates between 4-byte and 16-byte registers.
		{
			tname: "4-byte data eq within range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(1, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG_1, linux.NFT_RANGE_EQ, numToBE(0, 4), numToBE(5, 4)),
			res:   true,
		},
		{
			tname: "4-byte data neq within range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(4, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG_1, linux.NFT_RANGE_NEQ, numToBE(0, 4), numToBE(5, 4)),
			res:   false,
		},
		{
			tname: "4-byte data eq below range",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_00, newBytesData(numToBE(1, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG32_00, linux.NFT_RANGE_EQ, numToBE(3, 4), numToBE(5, 4)),
			res:   false,
		},
		{
			tname: "4-byte data neq below range",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_00, newBytesData(numToBE(1, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG32_00, linux.NFT_RANGE_NEQ, numToBE(3, 4), numToBE(5, 4)),
			res:   true,
		},
		{
			tname: "4-byte data eq above range",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_00, newBytesData(numToBE(954, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG32_00, linux.NFT_RANGE_EQ, numToBE(3, 4), numToBE(5, 4)),
			res:   false,
		},
		{
			tname: "4-byte data neq above range",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_00, newBytesData(numToBE(954, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG32_00, linux.NFT_RANGE_NEQ, numToBE(3, 4), numToBE(5, 4)),
			res:   true,
		},
		{
			tname: "4-byte data eq on lower bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_00, newBytesData(numToBE(1, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG32_00, linux.NFT_RANGE_EQ, numToBE(1, 4), numToBE(5, 4)),
			res:   true,
		},
		{
			tname: "4-byte data neq on lower bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_00, newBytesData(numToBE(1, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG32_00, linux.NFT_RANGE_NEQ, numToBE(1, 4), numToBE(5, 4)),
			res:   false,
		},
		{
			tname: "4-byte data eq on upper bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(100, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_EQ, numToBE(4, 4), numToBE(100, 4)),
			res:   true,
		},
		{
			tname: "4-byte data neq on upper bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(100, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_NEQ, numToBE(4, 4), numToBE(100, 4)),
			res:   false,
		},
		{
			tname: "4-byte data eq on point range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(123, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_EQ, numToBE(123, 4), numToBE(123, 4)),
			res:   true,
		},
		{
			tname: "4-byte data neq on point range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(123, 4))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_NEQ, numToBE(123, 4), numToBE(123, 4)),
			res:   false,
		},
		// 8-byte ranges.
		{
			tname: "8-byte data eq within range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(1, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_1, linux.NFT_RANGE_EQ, numToBE(0, 8), numToBE(5, 8)),
			res:   true,
		},
		{
			tname: "8-byte data neq within range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData(numToBE(4, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_2, linux.NFT_RANGE_NEQ, numToBE(0, 8), numToBE(5, 8)),
			res:   false,
		},
		{
			tname: "8-byte data eq below range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(numToBE(1, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_3, linux.NFT_RANGE_EQ, numToBE(3, 8), numToBE(5, 8)),
			res:   false,
		},
		{
			tname: "8-byte data neq below range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(1, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_NEQ, numToBE(3, 8), numToBE(5, 8)),
			res:   true,
		},
		{
			tname: "8-byte data eq above range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(954, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_1, linux.NFT_RANGE_EQ, numToBE(3, 8), numToBE(5, 8)),
			res:   false,
		},
		{
			tname: "8-byte data neq above range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData(numToBE(954, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_2, linux.NFT_RANGE_NEQ, numToBE(3, 8), numToBE(5, 8)),
			res:   true,
		},
		{
			tname: "8-byte data eq on lower bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(numToBE(1, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_3, linux.NFT_RANGE_EQ, numToBE(1, 8), numToBE(5, 8)),
			res:   true,
		},
		{
			tname: "8-byte data neq on lower bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(1, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_NEQ, numToBE(1, 8), numToBE(5, 8)),
			res:   false,
		},
		{
			tname: "8-byte data eq on upper bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(100, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_EQ, numToBE(4, 8), numToBE(100, 8)),
			res:   true,
		},
		{
			tname: "8-byte data neq on upper bound",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(100, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_NEQ, numToBE(4, 8), numToBE(100, 8)),
			res:   false,
		},
		{
			tname: "8-byte data eq on point range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(123, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_1, linux.NFT_RANGE_EQ, numToBE(123, 8), numToBE(123, 8)),
			res:   true,
		},
		{
			tname: "8-byte data neq on point range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(numToBE(123, 8))),
			op2:   mustCreateRanged(t, linux.NFT_REG_3, linux.NFT_RANGE_NEQ, numToBE(123, 8), numToBE(123, 8)),
			res:   false,
		},
		// simpler 16-byte ranges.
		{
			tname: "16-byte data eq within range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateRanged(t, linux.NFT_REG_1, linux.NFT_RANGE_EQ, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
		{
			tname: "16-byte data neq within range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateRanged(t, linux.NFT_REG_2, linux.NFT_RANGE_NEQ, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "16-byte data eq outside range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x45, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateRanged(t, linux.NFT_REG_3, linux.NFT_RANGE_EQ, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}),
			res:   false,
		},
		{
			tname: "16-byte data neq outside range",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x45, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			op2:   mustCreateRanged(t, linux.NFT_REG_4, linux.NFT_RANGE_NEQ, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}),
			res:   true,
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Adds drop operation. Will be final verdict if comparison is true.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}
			if test.res {
				if v.Code != VC(linux.NF_DROP) {
					t.Fatalf("expected verdict Drop for %t result, got %v", test.res, v)
				}
			} else {
				if v.Code != VC(linux.NF_ACCEPT) {
					t.Fatalf("expected base chain policy verdict Accept for %t result, got %v", test.res, v)
				}
			}
		})
	}
}

// TestEvaluatePayloadLoad tests that the Payload Load operation correctly loads
// the specified payload into the destination register.
// The nft binary commands used to generate these are stated above each test.
// All commands should be preceded by nft --debug=netlink.
// Note: Relies on expected behavior of the Comparison operation.
// TODO(b/339691111): Add tests for VLAN, ARP, ICMP, ICMPv6, IGMP, UDP headers.
func TestEvaluatePayloadLoad(t *testing.T) {
	// Sets testing packets.
	ethernetPacket := makeEthernetPacket(0, arbitraryEthernetFields())
	ipv4Packet := makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields())
	ipv6Packet := makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields())
	tcpPacket := makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields())

	for _, test := range []struct {
		tname string
		pkt   *stack.PacketBuffer
		op1   operation // Payload Load operation to test.
		op2   operation // Comparison operation to check resulting data in register,
		// nil if expecting a break during evaluation.
	}{
		// Ethernet header expression commands.
		{ // cmd: add rule ip tab ch ether saddr 02:02:03:04:05:06
			tname: "load ethernet header source address",
			pkt:   ethernetPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_LL_HEADER, ethSrcAddrOffset, ethSrcAddrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryLinkAddrB[:]),
		},
		{ // cmd: add rule ip tab ch ether daddr 02:02:03:04:05:07
			tname: "load ethernet header destination address",
			pkt:   ethernetPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_LL_HEADER, ethDstAddrOffset, ethDstAddrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryLinkAddrB2[:]),
		},
		{ // cmd: add rule ip tab ch ether type ip
			tname: "load ethernet header type",
			pkt:   ethernetPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_LL_HEADER, ethTypeOffset, ethTypeLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(int(arbitraryEthernetType), ethTypeLen)),
		},

		// IPv4 header expression commands.
		{ // cmd: add rule ip tab ch ip length 20
			tname: "load ipv4 header length",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4LengthOffset, ipv4LengthLen, linux.NFT_REG32_01),
			op2:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(header.IPv4MinimumSize, ipv4LengthLen)),
		},
		{ // cmd: add rule ip tab ch ip id 3
			tname: "load ipv4 header ip id",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4IDOffset, ipv4IDLen, linux.NFT_REG32_01),
			op2:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(arbitraryHeaderID, ipv4IDLen)),
		},
		{ // cmd: add rule ip tab ch ip frag-off 0
			tname: "load ipv4 header fragment offset",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4FragOffOffset, ipv4FragOffLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(0, ipv4FragOffLen)),
		},
		// Though the packet is fragmented, there should be no issue because we are
		// changing data within the network header.
		{ // cmd: add rule ip tab ch ip frag-off 2 (16 bytes)
			tname: "load ipv4 header fragment offset non zero for fragmented packet",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, fragmentedIPv4Fields()),
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 6, 2, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(arbitraryNonZeroFragmentOffset/8, ipv4FragOffLen)),
			// we divide by 8 because the fragment offset is in units of 8 bytes,
			// which is encoded into the packet in IPv4.Encode().
		},
		{ // cmd: add rule ip tab ch ip ttl 64
			tname: "load ipv4 header time to live",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4TTLOffset, ipv4TTLLen, linux.NFT_REG32_01),
			op2:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(arbitraryTimeToLive, ipv4TTLLen)),
		},
		{ // cmd: add rule ip tab ch ip protocol tcp
			tname: "load ipv4 header protocol",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4ProtocolOffset, ipv4ProtocolLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(int(tcpTransportProtocol), ipv4ProtocolLen)),
		},
		{ // cmd: add rule ip tab ch ip saddr 192.168.1.1
			tname: "load ipv4 header source address",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4SrcAddrOffset, ipv4SrcAddrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryIPv4AddrB[:]),
		},
		{ // cmd: add rule ip tab ch ip daddr 192.168.1.9
			tname: "load ipv4 header destination address",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4DstAddrOffset, ipv4DstAddrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryIPv4AddrB2[:]),
		},
		{ // cmd: add rule ip tab ch ip checksum __
			tname: "load ipv4 header checksum",
			pkt:   ipv4Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4ChecksumOffset, ipv4ChecksumLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(int(header.IPv4(ipv4Packet.NetworkHeader().Slice()).Checksum()), ipv4ChecksumLen)),
		},

		// IPv6 header expression commands.
		{ // cmd: add rule ip6 tab ch ip6 length 0
			tname: "load ipv6 header length",
			pkt:   ipv6Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6LengthOffset, ipv6LengthLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(0, ipv6LengthLen)),
		},
		{ // cmd: add rule ip6 tab ch ip6 nexthdr tcp
			tname: "load ipv6 header next header",
			pkt:   ipv6Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6NextHdrOffset, ipv6NextHdrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(int(tcpTransportProtocol), ipv6NextHdrLen)),
		},
		{ // cmd: add rule ip6 tab ch ip6 hoplimit 64
			tname: "load ipv6 header hop limit",
			pkt:   ipv6Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6HopLimitOffset, ipv6HopLimitLen, linux.NFT_REG32_01),
			op2:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(arbitraryTimeToLive, ipv6HopLimitLen)),
		},
		{ // cmd: add rule ip6 tab ch ip6 saddr 2001:db8:85a3::aa
			tname: "load ipv6 header source address",
			pkt:   ipv6Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6SrcAddrOffset, ipv6SrcAddrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryIPv6AddrB[:]),
		},
		{ // cmd: add rule ip6 tab ch ip6 daddr 2001:db8:85a3::bb
			tname: "load ipv6 header destination address",
			pkt:   ipv6Packet,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6DstAddrOffset, ipv6DstAddrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryIPv6AddrB2[:]),
		},

		// TCP header expression commands.
		// Since we are changing data within the transport header with a fragmented
		// IPv4 packet, this can be problematic, so the evaluation should break.
		{
			tname: "load for transport header with a fragmented ipv4 packet",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, fragmentedIPv4Fields(), arbitraryTCPFields()),
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, linux.NFT_REG_1),
			op2:   nil,
		},
		{ // cmd: add rule ip tab ch tcp sport 12345
			tname: "load tcp header source port",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSrcPortOffset, tcpSrcPortLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(arbitraryPort, tcpSrcPortLen)),
		},
		{ // cmd: add rule ip tab ch tcp dport 80
			tname: "load tcp header destination port",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpDstPortOffset, tcpDstPortLen, linux.NFT_REG32_01),
			op2:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(arbitraryPort2, tcpDstPortLen)),
		},
		{
			// cmd: add rule ip tab ch tcp sequence 32
			tname: "load tcp header sequence number",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSeqNumOffset, tcpSeqNumLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(tcpSeqNum, tcpSeqNumLen)),
		},
		{ // cmd: add rule ip tab ch tcp ackseq 165
			tname: "load tcp header acknowledgement sequence number",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpAckNumOffset, tcpAckNumLen, linux.NFT_REG32_01),
			op2:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(tcpAckNum, tcpAckNumLen)),
		},
		{ // cmd: add rule ip tab ch tcp window 65535
			tname: "load tcp header window",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpWindowOffset, tcpWindowLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(tcpWinSize, tcpWindowLen)),
		},
		{ // cmd: add rule ip tab ch tcp checksum __
			tname: "load tcp header checksum",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpChecksumOffset, tcpChecksumLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(int(header.TCP(tcpPacket.TransportHeader().Slice()).Checksum()), tcpChecksumLen)),
		},
		{ // cmd: add rule ip tab ch tcp urgptr 0
			tname: "load tcp header urgent pointer",
			pkt:   tcpPacket,
			op1:   mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpUrgPtrOffset, tcpUrgPtrLen, linux.NFT_REG_1),
			op2:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(tcpUrgentPointer, tcpUrgPtrLen)),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Adds drop operation. Will be final verdict if all comparisons are true.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation.
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, test.pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}

			// Checks for final verdict.
			if test.op2 == nil {
				// If no comparison operation is set, then payload load should break,
				// resulting in Accept as the default policy verdict.
				if v.Code != VC(linux.NF_ACCEPT) {
					t.Fatalf("expected verdict Accept for break during evaluation, got %v", v)
				}
			} else {
				// If a comparison operation is set, both payload load and comparison
				// should succeed, resulting in Drop as the final verdict.
				if v.Code != VC(linux.NF_DROP) {
					t.Fatalf("expected verdict Drop for true comparison, got %v", v)
				}
			}
		})
	}
}

// TestEvaluatePayloadSet tests that the Payload Set operation correctly sets
// the payload from the source register and updates the packet checksums.
// The nft binary commands used to generate these are stated above each test.
// All commands should be preceded by nft --debug=netlink.
// TODO(b/339691111): Add tests for VLAN, ARP, ICMP, ICMPv6, IGMP, UDP headers.
func TestEvaluatePayloadSet(t *testing.T) {
	for _, test := range []struct {
		tname  string
		pkt    *stack.PacketBuffer
		outPkt *stack.PacketBuffer // nil if expecting a break during evaluation.
		op1    operation           // Immediate operation to load source register.
		op2    operation           // Payload Set operation to test.
	}{
		// Ethernet header statement commands.
		{ // cmd: add rule ip tab ch ether saddr set 02:02:03:04:05:07
			tname: "set ethernet header source address",
			pkt:   makeEthernetPacket(0, arbitraryEthernetFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryEthernetFields()
				fields.SrcAddr = arbitraryLinkAddr2
				return makeEthernetPacket(0, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(arbitraryLinkAddrB2[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, ethSrcAddrOffset, ethSrcAddrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{ // cmd: add rule ip tab ch ether daddr set 02:02:03:04:05:06
			tname: "set ethernet header destination address",
			pkt:   makeEthernetPacket(0, arbitraryEthernetFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryEthernetFields()
				fields.DstAddr = arbitraryLinkAddr
				return makeEthernetPacket(0, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_2, newBytesData(arbitraryLinkAddrB[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, ethDstAddrOffset, ethDstAddrLen, linux.NFT_REG_2, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{ // cmd: add rule ip tab ch ether type set ip6
			tname: "set ethernet header type",
			pkt:   makeEthernetPacket(0, arbitraryEthernetFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryEthernetFields()
				fields.Type = header.IPv6ProtocolNumber
				return makeEthernetPacket(0, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(int(header.IPv6ProtocolNumber), ethTypeLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, ethTypeOffset, ethTypeLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},

		// IPv4 header statement commands.
		{ // cmd: add rule ip tab ch ip length set 30
			tname: "set ipv4 header length",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv4Fields()
				fields.TotalLength = uint16(30)
				return makeIPv4Packet(header.IPv4MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(30, ipv4LengthLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4LengthOffset, ipv4LengthLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip tab ch ip id set 12345
			tname: "set ipv4 header ip id",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv4Fields()
				fields.ID = uint16(12345)
				return makeIPv4Packet(header.IPv4MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(12345, ipv4IDLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4IDOffset, ipv4IDLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		// Note: Fragment offsets are divided by 8 because they are in units of 8
		// bytes, which is encoded into the packet in IPv4.Encode().
		{ // cmd: add rule ip tab ch ip frag-off set 2 (16 bytes)
			tname:  "set ipv4 header fragment offset, set fragment on",
			pkt:    makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: makeIPv4Packet(header.IPv4MinimumSize, fragmentedIPv4Fields()),
			op1:    mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(arbitraryNonZeroFragmentOffset/8, ipv4FragOffLen))),
			op2:    mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4FragOffOffset, ipv4FragOffLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		{ // cmd: add rule ip tab ch ip frag-off set 0
			tname:  "set ipv4 header fragment offset, set fragment off for fragmented packet",
			pkt:    makeIPv4Packet(header.IPv4MinimumSize, fragmentedIPv4Fields()),
			outPkt: makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			op1:    mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0, ipv4FragOffLen))),
			op2:    mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4FragOffOffset, ipv4FragOffLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		{ // cmd: add rule ip tab ch ip frag-off set 10 (80 bytes)
			tname: "set ipv4 header fragment offset, change fragment offset for fragmented packet",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, fragmentedIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv4Fields()
				fields.FragmentOffset = uint16(10 * 8)
				return makeIPv4Packet(header.IPv4MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(10, ipv4FragOffLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4FragOffOffset, ipv4FragOffLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		{ // cmd: add rule ip tab ch ip ttl set 128
			tname: "set ipv4 time to live",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv4Fields()
				fields.TTL = uint8(128)
				return makeIPv4Packet(header.IPv4MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(128, ipv4TTLLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4TTLOffset, ipv4TTLLen, linux.NFT_REG32_01, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		{ // cmd: add rule ip tab ch ip saddr set 192.168.1.9
			tname: "set ipv4 header source address",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv4Fields()
				fields.SrcAddr = tcpip.AddrFrom4(arbitraryIPv4AddrB2)
				return makeIPv4Packet(header.IPv4MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(arbitraryIPv4AddrB2[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4SrcAddrOffset, ipv4SrcAddrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip tab ch ip daddr set 192.168.1.1
			tname: "set ipv4 header destination address",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv4Fields()
				fields.DstAddr = tcpip.AddrFrom4(arbitraryIPv4AddrB)
				return makeIPv4Packet(header.IPv4MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(arbitraryIPv4AddrB[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4DstAddrOffset, ipv4DstAddrLen, linux.NFT_REG_4, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip tab ch ip checksum set 6060
			tname: "set ipv4 header checksum",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				pkt := makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields())
				pkt.Network().SetChecksum(6060)
				return pkt
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(6060, ipv4ChecksumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4ChecksumOffset, ipv4ChecksumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},

		// IPv6 header statement commands.
		{ // cmd: add rule ip6 tab ch ip6 length set 232
			tname: "set ipv6 header length",
			pkt:   makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.PayloadLength = uint16(232)
				return makeIPv6Packet(header.IPv6MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(232, ipv6LengthLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6LengthOffset, ipv6LengthLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip6 tab ch ip6 hoplimit set 54
			tname: "set ipv6 header hop limit",
			pkt:   makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.HopLimit = uint8(54)
				return makeIPv6Packet(header.IPv6MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(54, ipv6HopLimitLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6HopLimitOffset, ipv6HopLimitLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{ // cmd: add rule ip6 tab ch ip6 saddr set 2001:db8:85a3::bb
			tname: "set ipv6 header source address",
			pkt:   makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.SrcAddr = tcpip.AddrFrom16(arbitraryIPv6AddrB2)
				return makeIPv6Packet(header.IPv6MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(arbitraryIPv6AddrB2[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6SrcAddrOffset, ipv6SrcAddrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip6 tab ch ip6 daddr set 2001:db8:85a3::aa
			tname: "set ipv6 header destination address",
			pkt:   makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.DstAddr = tcpip.AddrFrom16(arbitraryIPv6AddrB)
				return makeIPv6Packet(header.IPv6MinimumSize, fields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(arbitraryIPv6AddrB[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6DstAddrOffset, ipv6DstAddrLen, linux.NFT_REG_3, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},

		// TCP with IPv4 header statement commands.
		// TCP set commands.
		{
			// Since we change data within the transport header with a fragmented
			// IPv4 packet, this can be problematic, so the evaluation should break.
			tname:  "set for transport header with a fragmented ipv4 packet",
			pkt:    makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, fragmentedIPv4Fields(), arbitraryTCPFields()),
			outPkt: nil,
			op1:    mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(arbitraryPort, tcpSrcPortLen))),
			op2:    mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSrcPortOffset, tcpSrcPortLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp sport set 80
			tname: "set tcp header with ipv4 source port",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.SrcPort = arbitraryPort2
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(arbitraryPort2, tcpSrcPortLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSrcPortOffset, tcpSrcPortLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp dport set 12345
			tname: "set tcp header with ipv4 destination port",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.DstPort = arbitraryPort
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(arbitraryPort, tcpDstPortLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpDstPortOffset, tcpDstPortLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp sequence set 33
			tname: "set tcp header with ipv4 sequence number",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.SeqNum = uint32(33)
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(33, tcpSeqNumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSeqNumOffset, tcpSeqNumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp ackseq set 245
			tname: "set tcp header with ipv4 acknowledgement sequence number",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.AckNum = uint32(245)
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(245, tcpAckNumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpAckNumOffset, tcpAckNumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp window set 91
			tname: "set tcp header with ipv4 window",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.WindowSize = 91
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(91, tcpWindowLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpWindowOffset, tcpWindowLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp checksum set 7654
			tname: "set tcp header with ipv4 checksum",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				pkt := makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields())
				tcpHdr := header.TCP(pkt.TransportHeader().Slice())
				tcpHdr.SetChecksum(7654)
				return pkt
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(7654, tcpChecksumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpChecksumOffset, tcpChecksumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp urgptr set 40
			tname: "set tcp header with ipv4 urgent pointer",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.UrgentPointer = 40
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(40, tcpUrgPtrLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpUrgPtrOffset, tcpUrgPtrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		// IPv4 set commands.
		{ // cmd: add rule ip tab ch ip id set 12345
			tname: "set ipv4 header with tcp ip id",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				ipFields := arbitraryIPv4Fields()
				ipFields.ID = uint16(12345)
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, ipFields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(12345, ipv4IDLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4IDOffset, ipv4IDLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		{ // cmd: add rule ip tab ch ip ttl set 128
			tname: "set ipv4 time to live",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				ipFields := arbitraryIPv4Fields()
				ipFields.TTL = uint8(128)
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, ipFields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(128, ipv4TTLLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4TTLOffset, ipv4TTLLen, linux.NFT_REG32_01, linux.NFT_PAYLOAD_CSUM_INET, 10, 0x0),
		},
		{ // cmd: add rule ip tab ch ip saddr set 192.168.1.9
			tname: "set ipv4 header with tcp source address",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				ipFields := arbitraryIPv4Fields()
				ipFields.SrcAddr = tcpip.AddrFrom4(arbitraryIPv4AddrB2)
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, ipFields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(arbitraryIPv4AddrB2[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4SrcAddrOffset, ipv4SrcAddrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip tab ch ip daddr set 192.168.1.1
			tname: "set ipv4 header with tcp destination address",
			pkt:   makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, arbitraryIPv4Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				ipFields := arbitraryIPv4Fields()
				ipFields.DstAddr = tcpip.AddrFrom4(arbitraryIPv4AddrB)
				return makeIPv4TCPPacket(header.IPv4MinimumSize+header.TCPMinimumSize, ipFields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(arbitraryIPv4AddrB[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4DstAddrOffset, ipv4DstAddrLen, linux.NFT_REG_4, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},

		// TCP on IPv6 header statement commands.
		// TCP set commands.
		{ // cmd: add rule ip tab ch tcp sport set 80
			tname: "set tcp header with ipv6 source port",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.SrcPort = arbitraryPort2
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(arbitraryPort2, tcpSrcPortLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSrcPortOffset, tcpSrcPortLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp dport set 12345
			tname: "set tcp header with ipv6 destination port",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.DstPort = arbitraryPort
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(arbitraryPort, tcpDstPortLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpDstPortOffset, tcpDstPortLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp sequence set 33
			tname: "set tcp header with ipv6 sequence number",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.SeqNum = uint32(33)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(33, tcpSeqNumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpSeqNumOffset, tcpSeqNumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp ackseq set 245
			tname: "set tcp header with ipv6 acknowledgement sequence number",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.AckNum = uint32(245)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(245, tcpAckNumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpAckNumOffset, tcpAckNumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp window set 91
			tname: "set tcp header with ipv6 window",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.WindowSize = uint16(91)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(91, tcpWindowLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpWindowOffset, tcpWindowLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp checksum set 7654
			tname: "set tcp header with ipv6 checksum",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				pkt := makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields())
				tcpHdr := header.TCP(pkt.TransportHeader().Slice())
				tcpHdr.SetChecksum(7654)
				return pkt
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(7654, tcpChecksumLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpChecksumOffset, tcpChecksumLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{ // cmd: add rule ip tab ch tcp urgptr set 40
			tname: "set tcp header with ipv6 urgent pointer",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				tcpFields := arbitraryTCPFields()
				tcpFields.UrgentPointer = uint16(40)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), tcpFields)
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(40, tcpUrgPtrLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, tcpUrgPtrOffset, tcpUrgPtrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		// IPv6 set commands.
		{ // cmd: add rule ip6 tab ch ip6 length set 232
			tname: "set ipv6 header length",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.PayloadLength = uint16(232)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, fields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(232, ipv6LengthLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6LengthOffset, ipv6LengthLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip6 tab ch ip6 hoplimit set 54
			tname: "set ipv6 header hop limit",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.HopLimit = uint8(54)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, fields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(54, ipv6HopLimitLen))),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6HopLimitOffset, ipv6HopLimitLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{ // cmd: add rule ip6 tab ch ip6 saddr set 2001:db8:85a3::bb
			tname: "set ipv6 header source address",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.SrcAddr = tcpip.AddrFrom16(arbitraryIPv6AddrB2)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, fields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(arbitraryIPv6AddrB2[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6SrcAddrOffset, ipv6SrcAddrLen, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{ // cmd: add rule ip6 tab ch ip6 daddr set 2001:db8:85a3::aa
			tname: "set ipv6 header destination address",
			pkt:   makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, arbitraryIPv6Fields(), arbitraryTCPFields()),
			outPkt: func() *stack.PacketBuffer {
				fields := arbitraryIPv6Fields()
				fields.DstAddr = tcpip.AddrFrom16(arbitraryIPv6AddrB)
				return makeIPv6TCPPacket(header.IPv6MinimumSize+header.TCPMinimumSize, fields, arbitraryTCPFields())
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(arbitraryIPv6AddrB[:])),
			op2: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv6DstAddrOffset, ipv6DstAddrLen, linux.NFT_REG_3, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Adds drop operation. Will be final verdict if payload set evaluation is
			// successful (operation breaks if anything goes wrong).
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation.
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, test.pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}

			// Checks for final verdict.
			if test.outPkt == nil {
				// If no output packet is expected, then evaluation should break,
				// resulting in Accept as the default policy verdict.
				if v.Code != VC(linux.NF_ACCEPT) {
					t.Fatalf("expected verdict Accept for break during evaluation, got %v", v)
				}
				return
			} else {
				// If an output packet is expected, the evaluation should go until end
				// of rule (no errors/breaks), resulting in Drop as the final verdict.
				if v.Code != VC(linux.NF_DROP) {
					t.Fatalf("expected verdict Drop for successful evaluation, got %v", v)
				}
			}

			// Checks if the packet are equal.
			checkPacketEquality(t, test.outPkt, test.pkt)
		})
	}
}

// TestEvaluateBitwise tests that the Bitwise operation correctly performs the
// appropriate bitwise operation on the source register data and stores the
// result in the destination register.
// Note: Relies on expected behavior of the Immediate and Comparison operation.
func TestEvaluateBitwise(t *testing.T) {
	for _, test := range []struct {
		tname string
		op1   operation // Immediate operation to set source register.
		op2   operation // Bitwise operation to test.
		op3   operation // Comparison operation to validate result.
	}{
		// Bitwise bool operations.
		// cmd: add rule ip filter input ip saddr and _ or _ == 105
		{
			tname: "same 4-byte register with 4-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(4783, 4))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG32_01, linux.NFT_REG32_01, numToBE(55, 4), numToBE(78, 4)),
			op3:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE((4783&55)^78, 4)),
		},
		{
			tname: "same 16-byte register with 4-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(4783, 4))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG_1, linux.NFT_REG_1, numToBE(55, 4), numToBE(78, 4)),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE((4783&55)^78, 4)),
		},
		// cmd: add rule ip filter input ip saddr and 0x11111111 == 285217024
		{
			tname: "dif 4-byte registers with 4-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(400700800, 4))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG32_01, linux.NFT_REG32_02, numToBE(0x11111111, 4), numToBE(0, 4)),
			op3:   mustCreateComparison(t, linux.NFT_REG32_02, linux.NFT_CMP_EQ, numToBE(400700800&0x11111111, 4)),
		},
		{
			tname: "dif 16-byte registers with 4-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(400700800, 4))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG_1, linux.NFT_REG_2, numToBE(0x11111111, 4), numToBE(0, 4)),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, numToBE(400700800&0x11111111, 4)),
		},
		// add rule ip filter input ip saddr or 0xff0230ff == 267583535
		{
			tname: "4- and 16-byte registers with 4-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_10, newBytesData(numToBE(0, 4))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG32_10, linux.NFT_REG_2, numToBE(0x00cffd00, 4), numToBE(0xff3002ff, 4)),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, numToBE((0&0x00cffd00)^0xff3002ff, 4)),
		},
		{
			tname: "16- and 4-byte registers with 4-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(numToBE(0, 4))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG_3, linux.NFT_REG32_05, numToBE(0x00cffd00, 4), numToBE(0xff3002ff, 4)),
			op3:   mustCreateComparison(t, linux.NFT_REG32_05, linux.NFT_CMP_EQ, numToBE((0&0x00cffd00)^0xff3002ff, 4)),
		},
		{
			tname: "8-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x12345678, 8))),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG_1, linux.NFT_REG_1, numToBE(0x00cffd00, 8), numToBE(0xff3002ff, 8)),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE((0x12345678&0x00cffd00)^0xff3002ff, 8)),
		},
		{
			tname: "16-byte data for bitwise bool",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})),
			op2:   mustCreateBitwiseBool(t, linux.NFT_REG_4, linux.NFT_REG_2, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
		},
		// Bitwise shift operations.
		// No nft binary commands were observed that directly used shift operations.
		{
			tname: "0 shift left for bitwise lshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(4783, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG32_01, linux.NFT_REG32_01, 4, 0, false),
			op3:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, numToBE(4783, 4)),
		},
		{
			tname: "0 shift right for bitwise rshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(4783, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG_1, linux.NFT_REG_1, 4, 0, true),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, numToBE(4783, 4)),
		},
		{
			tname: "1-bit shift left for bitwise lshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(4782, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG_4, linux.NFT_REG_4, 4, 1, false),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, numToBE(4782<<1, 4)),
		},
		{
			tname: "1-bit shift right for bitwise rshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_06, newBytesData(numToBE(4782, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG32_06, linux.NFT_REG32_06, 4, 1, true),
			op3:   mustCreateComparison(t, linux.NFT_REG32_06, linux.NFT_CMP_EQ, numToBE(4782>>1, 4)),
		},
		{
			tname: "8-bit shift left for bitwise lshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(4782, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG_4, linux.NFT_REG_4, 4, 8, false),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, numToBE(4782<<8, 4)),
		},
		{
			tname: "8-bit shift right for bitwise rshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_06, newBytesData(numToBE(4782, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG32_06, linux.NFT_REG32_06, 4, 8, true),
			op3:   mustCreateComparison(t, linux.NFT_REG32_06, linux.NFT_CMP_EQ, numToBE(4782>>8, 4)),
		},
		{
			tname: "16-bit shift left for bitwise lshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(0x45678910, 8))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG_4, linux.NFT_REG_4, 8, 16, false),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, numToBE(0x45678910<<16, 8)),
		},
		{
			tname: "16-bit shift right for bitwise rshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_06, newBytesData(numToBE(0x45678910, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG32_06, linux.NFT_REG32_06, 4, 16, true),
			op3:   mustCreateComparison(t, linux.NFT_REG32_06, linux.NFT_CMP_EQ, numToBE(0x45678910>>16, 4)),
		},
		{
			tname: "max-bit shift left for bitwise lshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_03, newBytesData(numToBE(0x45678910, 4))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG32_03, linux.NFT_REG_2, 4, bitshiftLimit-1, false),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, numToBE(0x45678910<<(bitshiftLimit-1), 4)),
		},
		{
			tname: "max-bit shift right for bitwise rshift",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData(numToBE(0x45678910, 8))),
			op2:   mustCreateBitwiseShift(t, linux.NFT_REG_3, linux.NFT_REG_2, 8, bitshiftLimit-1, true),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, numToBE(0x45678910>>(bitshiftLimit-1), 8)),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}
			if test.op3 != nil {
				rule.addOperation(test.op3)
			}

			// Adds drop operation. Will be final verdict if comparison is true.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}
			if v.Code != VC(linux.NF_DROP) {
				t.Fatalf("expected verdict Drop for true comparison, got %v", v)
			}
		})
	}
}

// TestEvaluateCounter tests that the Counter operation correctly increments the
// counter for the number of bytes and packets as it encounters packets.
// Note: relies on expected behavior of Comparison and Payload Load operations.
func TestEvaluateCounter(t *testing.T) {
	// Creates a counter operation.
	counter := newCounter(0, 0)
	// Defines the packets to be used in the test.
	desiredIpv4Address := tcpip.AddrFrom4(arbitraryIPv4AddrB)
	countedIPv4Pkt := func() *stack.PacketBuffer {
		fields := arbitraryIPv4Fields()
		fields.SrcAddr = desiredIpv4Address
		return makeIPv4Packet(header.IPv4MinimumSize, fields)
	}
	uncountedIPv4Pkt := func() *stack.PacketBuffer {
		fields := arbitraryIPv4Fields()
		fields.SrcAddr = tcpip.AddrFrom4(arbitraryIPv4AddrB2)
		return makeIPv4Packet(header.IPv4MinimumSize, fields)
	}
	pkts := []*stack.PacketBuffer{countedIPv4Pkt(), uncountedIPv4Pkt(), countedIPv4Pkt(), countedIPv4Pkt(),
		uncountedIPv4Pkt(), countedIPv4Pkt(), uncountedIPv4Pkt(), uncountedIPv4Pkt(), uncountedIPv4Pkt(), countedIPv4Pkt()}
	t.Run("counter increment tests", func(t *testing.T) {
		// Sets up an NFTables object with a base chain with policy accept.
		nf := newNFTablesStd()
		tab, err := nf.AddTable(arbitraryFamily, "test", false)
		if err != nil {
			t.Fatalf("unexpected error for AddTable: %v", err)
		}
		bc, err := tab.AddChain("base_chain", nil, "test chain", false)
		if err != nil {
			t.Fatalf("unexpected error for AddChain: %v", err)
		}
		bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)

		// Creates a rule that filters for the desired IPv4 address and adds the
		// counter to the end of the rule. So, the counter should only increment for
		// packets that satisfy the comparison.
		rule := &Rule{}
		rule.addOperation(mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, ipv4SrcAddrOffset, ipv4SrcAddrLen, linux.NFT_REG_1))
		rule.addOperation(mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, desiredIpv4Address.AsSlice()))
		rule.addOperation(counter)
		if err := bc.RegisterRule(rule, -1); err != nil {
			t.Fatalf("unexpected error for RegisterRule: %v", err)
		}

		// Runs evaluation for each packet and checks whether the counter has
		// incremented correctly.
		prevBytes := counter.bytes.Load()
		prevPackets := counter.packets.Load()
		for i, pkt := range pkts {
			_, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook for packet %d: %v", i, err)
			}
			// Checks whether the counter should have incremented for the packet.
			expectedDBytes, expectedDPackets := int64(0), int64(0)
			if pkt.Network().SourceAddress() == desiredIpv4Address {
				expectedDBytes, expectedDPackets = int64(pkt.Size()), 1
			}
			// Checks that the counter incremented correctly.
			newBytes := counter.bytes.Load()
			newPackets := counter.packets.Load()
			if dBytes := newBytes - prevBytes; dBytes != expectedDBytes {
				t.Fatalf("counter bytes incremented by %d for packet %d, expected %d", dBytes, i, expectedDBytes)
			}
			if dPackets := newPackets - prevPackets; dPackets != expectedDPackets {
				t.Fatalf("counter packets incremented by %d for packet %d, expected %d", dPackets, i, expectedDPackets)
			}
			// Updates the previous values for the next packet.
			prevBytes = newBytes
			prevPackets = newPackets
		}
	})
}

// TestEvaluateLast tests that the Last operation correctly records the last
// time the operation was evaluated.
func TestEvaluateLast(t *testing.T) {
	// Creates last operation and number of elapses (in milliseconds) for testing.
	last := &last{}
	elapses := []int64{0, 1000, 500, 1000, 100, 200, 300, 20000, 50, 700}
	totalElapsed := make([]int64, len(elapses))
	copy(totalElapsed, elapses)

	t.Run("last timing tests", func(t *testing.T) {
		// Makes an arbitrary packet to be used in the test.
		pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)

		// Sets up an NFTables object with a base chain and fake manual clock.
		fakeClock := faketime.NewManualClock()
		fixedRNG := rand.RNGFrom(&fixedReader{})
		nf := NewNFTables(fakeClock, fixedRNG)
		tab, err := nf.AddTable(arbitraryFamily, "test", false)
		if err != nil {
			t.Fatalf("unexpected error for AddTable: %v", err)
		}
		bc, err := tab.AddChain("base_chain", nil, "test chain", false)
		if err != nil {
			t.Fatalf("unexpected error for AddChain: %v", err)
		}
		bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)

		// Registers a single rule with the last operation.
		rule := &Rule{}
		rule.addOperation(last)
		if err := bc.RegisterRule(rule, -1); err != nil {
			t.Fatalf("unexpected error for RegisterRule: %v", err)
		}

		// Sets up a wait group to wait for all AfterFunc goroutines to complete.
		var wg sync.WaitGroup
		wg.Add(len(elapses))
		defer wg.Wait()

		// Calls EvaluateHook for each elapse and checks that the last operation
		// recorded the correct timestamp and has the set flag set.
		startStamp := nf.startTime.UnixMilli()
		clock := nf.clock
		for i := range elapses {
			// Uses totalElapsed slice to avoid race conditions.
			if i != 0 {
				totalElapsed[i] += totalElapsed[i-1]
			}
			clock.AfterFunc(time.Duration(totalElapsed[i])*time.Millisecond, func() {
				// Decrements wait group counter at end to signal func has completed.
				defer wg.Done()

				// Evaluates the packet (which should update last's timestamp).
				_, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
				if err != nil {
					t.Fatalf("unexpected error for EvaluateHook for packet %d: %v", i, err)
				}

				// Checks the set flag and the timestamp via total elapsed time.
				if !last.set.Load() {
					t.Fatalf("last operation not set for packet %d", i)
				}
				if dTotal := last.timestampMS.Load() - startStamp; dTotal != totalElapsed[i] {
					t.Fatalf("last operation recorded %d milliseconds since start for packet %d, expected %d", dTotal, i, totalElapsed[i])
				}
			})
		}
		// Manually advances the clock to trigger the AfterFunc goroutines.
		for _, elapse := range elapses {
			fakeClock.Advance(time.Duration(elapse) * time.Millisecond)
		}
	})
}

// TestEvaluateRoute tests that the Route operation correctly loads the specific
// route data into into the destination register.
// The nft binary commands used to generate these are stated above each test.
// Also note that all these commands mirror the ones in TestInterpretRouteOps.
// All commands should be preceded by nft --debug=netlink.
// Note: Relies on expected behavior of the Comparison operation.
func TestEvaluateRoute(t *testing.T) {
	for _, test := range []struct {
		tname string
		pkt   *stack.PacketBuffer
		op1   operation // Route operation to test.
		op2   operation // Comparison operation to check resulting data in register,
	}{
		// IPv4 Next Hop Commands
		{ // cmd: add rule ip filter output rt nexthop 192.168.1.1
			tname: "load nexthop4 key to 4-byte register",
			pkt: func() *stack.PacketBuffer {
				pkt := makeIPv4Packet(header.IPv6MinimumSize, arbitraryIPv4Fields())
				pkt.EgressRoute.NextHop = tcpip.AddrFrom4(arbitraryIPv4AddrB)
				return pkt
			}(),
			op1: mustCreateRoute(t, linux.NFT_RT_NEXTHOP4, linux.NFT_REG32_06),
			op2: mustCreateComparison(t, linux.NFT_REG32_06, linux.NFT_CMP_EQ, arbitraryIPv4AddrB[:]),
		},
		{ // cmd: add rule ip filter output rt nexthop 192.168.1.9
			tname: "load nexthop4 key to 16-byte register",
			pkt: func() *stack.PacketBuffer {
				pkt := makeIPv4Packet(header.IPv6MinimumSize, arbitraryIPv4Fields())
				pkt.EgressRoute.NextHop = tcpip.AddrFrom4(arbitraryIPv4AddrB2)
				return pkt
			}(),
			op1: mustCreateRoute(t, linux.NFT_RT_NEXTHOP4, linux.NFT_REG_3),
			op2: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_EQ, arbitraryIPv4AddrB2[:]),
		},
		// IPv6 Next Hop Commands
		{ // cmd: add rule ip filter output rt nexthop 2001:db8:85a3::aa
			tname: "load nexthop6 key to 16-byte register",
			pkt: func() *stack.PacketBuffer {
				pkt := makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields())
				pkt.EgressRoute.NextHop = tcpip.AddrFrom16(arbitraryIPv6AddrB)
				return pkt
			}(),
			op1: mustCreateRoute(t, linux.NFT_RT_NEXTHOP6, linux.NFT_REG_1),
			op2: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, arbitraryIPv6AddrB[:]),
		},
		// TCP Maximum Segment Size Commands
		{ // cmd: add rule ip filter output rt mtu 1500
			tname: "load tcpmss key to 4-byte register",
			pkt: func() *stack.PacketBuffer {
				pkt := makeIPv4Packet(header.IPv6MinimumSize, arbitraryIPv4Fields())
				pkt.GSOOptions.MSS = 1500
				return pkt
			}(),
			op1: mustCreateRoute(t, linux.NFT_RT_TCPMSS, linux.NFT_REG32_00),
			op2: mustCreateComparison(t, linux.NFT_REG32_00, linux.NFT_CMP_EQ, binary.NativeEndian.AppendUint16(nil, 1500)),
		},
		{ // cmd: add rule ip filter output rt mtu 0x0102
			tname: "load tcpmss key to 16-byte register",
			pkt: func() *stack.PacketBuffer {
				pkt := makeIPv6Packet(header.IPv6MinimumSize, arbitraryIPv6Fields())
				pkt.GSOOptions.MSS = 0x0102
				return pkt
			}(),
			op1: mustCreateRoute(t, linux.NFT_RT_TCPMSS, linux.NFT_REG_4),
			op2: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, binary.NativeEndian.AppendUint16(nil, 0x0102)),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Adds drop operation. Will be final verdict if all comparisons are true.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation.
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, test.pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}

			// Checks for final verdict (should be Drop if comparisons are true).
			if v.Code != VC(linux.NF_DROP) {
				t.Fatalf("expected verdict Drop for true comparison, got %v", v)
			}
		})
	}
}

// TestEvaluateByteorder tests that the Byteorder operation correctly performs
// the appropriate byteorder operation on the source register data and stores
// the result in the destination register.
// Note: Relies on expected behavior of the Immediate and Comparison operation.
func TestEvaluateByteorder(t *testing.T) {
	// Given a big endian and little endian byte slice of the same number, returns
	// the correct byte slice based on the host endianness.
	// Note: Uses enclosure so endianness doesn't need to be passed as an arg or
	// rechecked for every call.
	chooseOrder := func() func([]byte, []byte) []byte {
		hostBytes := binary.NativeEndian.AppendUint16(nil, 0x0102)
		isBigEndian := hostBytes[0] == 0x01
		return func(big, little []byte) []byte {
			if isBigEndian {
				return big
			}
			return little
		}
	}()
	// Like createChooseOrder but takes ints instead of byte slices.
	chooseOrderN := func(big, little, size int) []byte {
		return chooseOrder(numToBE(big, size), numToBE(little, size))
	}
	for _, test := range []struct {
		tname string
		op1   operation // Immediate operation to set source register.
		op2   operation // Byteorder operation to test.
		op3   operation // Comparison operation to validate result.
	}{
		// Size 2 tests (Lengths 2, 3, 4, 6, 8, 16)
		{
			tname: "ntoh size 2 len 2",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(0x0102, 2))),
			op2:   mustCreateByteorder(t, linux.NFT_REG32_01, linux.NFT_REG32_01, linux.NFT_BYTEORDER_NTOH, 2, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, chooseOrderN(0x0102, 0x0201, 2)),
		},
		{
			tname: "hton size 2 len 2",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(0x0102, 2))),
			op2:   mustCreateByteorder(t, linux.NFT_REG32_01, linux.NFT_REG_1, linux.NFT_BYTEORDER_HTON, 2, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, chooseOrderN(0x0102, 0x0201, 2)),
		},
		{
			tname: "ntoh size 2 len 3",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_01, newBytesData(numToBE(0x010203, 3))),
			op2:   mustCreateByteorder(t, linux.NFT_REG32_01, linux.NFT_REG_1, linux.NFT_BYTEORDER_NTOH, 3, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, chooseOrderN(0x010203, 0x020100, 3)),
		},
		{
			tname: "hton size 2 len 3",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x010203, 3))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG32_01, linux.NFT_BYTEORDER_HTON, 3, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ, chooseOrderN(0x010203, 0x020100, 3)),
		},
		{
			tname: "ntoh size 2 len 4",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_10, newBytesData(numToBE(0x01020304, 4))),
			op2:   mustCreateByteorder(t, linux.NFT_REG32_10, linux.NFT_REG32_05, linux.NFT_BYTEORDER_NTOH, 4, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG32_05, linux.NFT_CMP_EQ, chooseOrderN(0x01020304, 0x02010403, 4)),
		},
		{
			tname: "hton size 2 len 4",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(0x01020304, 4))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG32_09, linux.NFT_BYTEORDER_HTON, 4, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG32_09, linux.NFT_CMP_EQ, chooseOrderN(0x01020304, 0x02010403, 4)),
		},
		{
			tname: "ntoh size 2 len 6",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x010203040506, 6))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_1, linux.NFT_BYTEORDER_NTOH, 6, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, chooseOrderN(0x010203040506, 0x020104030605, 6)),
		},
		{
			tname: "hton size 2 len 6",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x010203040506, 6))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_1, linux.NFT_BYTEORDER_HTON, 6, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, chooseOrderN(0x010203040506, 0x020104030605, 6)),
		},
		{
			tname: "ntoh size 2 len 8",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x0102030405060708, 8))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_4, linux.NFT_BYTEORDER_NTOH, 8, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrderN(0x0102030405060708, 0x0201040306050807, 8)),
		},
		{
			tname: "hton size 2 len 8",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x0102030405060708, 8))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_4, linux.NFT_BYTEORDER_HTON, 8, 2),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrderN(0x0102030405060708, 0x0201040306050807, 8)),
		},
		{
			tname: "ntoh size 2 len 16",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_3, linux.NFT_REG_2, linux.NFT_BYTEORDER_NTOH, 16, 2),
			op3: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				[]byte{0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07, 0x0a, 0x09, 0x0c, 0x0b, 0x0e, 0x0d, 0x10, 0x0f})),
		},
		{
			tname: "hton size 2 len 16",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_3, linux.NFT_REG_2, linux.NFT_BYTEORDER_HTON, 16, 2),
			op3: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				[]byte{0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07, 0x0a, 0x09, 0x0c, 0x0b, 0x0e, 0x0d, 0x10, 0x0f})),
		},
		// Size 4 tests (Lengths 4, 6, 8, 16)
		{
			tname: "ntoh size 4 len 4",
			op1:   mustCreateImmediate(t, linux.NFT_REG32_05, newBytesData(numToBE(0x01020304, 4))),
			op2:   mustCreateByteorder(t, linux.NFT_REG32_05, linux.NFT_REG_2, linux.NFT_BYTEORDER_NTOH, 4, 4),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrderN(0x01020304, 0x04030201, 4)),
		},
		{
			tname: "hton size 4 len 4",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(0x01020304, 4))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG32_09, linux.NFT_BYTEORDER_HTON, 4, 4),
			op3:   mustCreateComparison(t, linux.NFT_REG32_09, linux.NFT_CMP_EQ, chooseOrderN(0x01020304, 0x04030201, 4)),
		},
		{
			tname: "ntoh size 4 len 6",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(0x010203040506, 6))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG_2, linux.NFT_BYTEORDER_NTOH, 6, 4),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrderN(0x010203040506, 0x040302010000, 6)),
		},
		{
			tname: "hton size 4 len 6",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData(numToBE(0x010203040506, 6))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG_2, linux.NFT_BYTEORDER_HTON, 6, 4),
			op3:   mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrderN(0x010203040506, 0x040302010000, 6)),
		},
		{
			tname: "ntoh size 4 len 8",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x0102030405060708, 8))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_4, linux.NFT_BYTEORDER_NTOH, 8, 4),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrderN(0x0102030405060708, 0x0403020108070605, 8)),
		},
		{
			tname: "hton size 4 len 8",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x0102030405060708, 8))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_4, linux.NFT_BYTEORDER_HTON, 8, 4),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrderN(0x0102030405060708, 0x0403020108070605, 8)),
		},
		{
			tname: "ntoh size 4 len 16",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_3, linux.NFT_REG_2, linux.NFT_BYTEORDER_NTOH, 16, 4),
			op3: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				[]byte{0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e, 0x0d})),
		},
		{
			tname: "hton size 4 len 16",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_3, linux.NFT_REG_2, linux.NFT_BYTEORDER_HTON, 16, 4),
			op3: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				[]byte{0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e, 0x0d})),
		},
		// Size 8 tests (Lengths 8, 12, 16)
		{
			tname: "ntoh size 8 len 8",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x0102030405060708, 8))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_4, linux.NFT_BYTEORDER_NTOH, 8, 8),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrderN(0x0102030405060708, 0x0807060504030201, 8)),
		},
		{
			tname: "hton size 8 len 8",
			op1:   mustCreateImmediate(t, linux.NFT_REG_1, newBytesData(numToBE(0x0102030405060708, 8))),
			op2:   mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_4, linux.NFT_BYTEORDER_HTON, 8, 8),
			op3:   mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrderN(0x0102030405060708, 0x0807060504030201, 8)),
		},
		{
			tname: "ntoh size 8 len 12",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_3, linux.NFT_REG_2, linux.NFT_BYTEORDER_NTOH, 12, 8),
			op3: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
				[]byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname: "hton size 8 len 12",
			op1:   mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_3, linux.NFT_REG_2, linux.NFT_BYTEORDER_HTON, 12, 8),
			op3: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
				[]byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname: "ntoh size 8 len 16",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG_4, linux.NFT_BYTEORDER_NTOH, 16, 8),
			op3: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				[]byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09})),
		},
		{
			tname: "hton size 8 len 16",
			op1:   mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})),
			op2:   mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG_4, linux.NFT_BYTEORDER_HTON, 16, 8),
			op3: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ, chooseOrder([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				[]byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09})),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}
			if test.op3 != nil {
				rule.addOperation(test.op3)
			}

			// Adds drop operation. Will be final verdict if comparison is true.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}
			if v.Code != VC(linux.NF_DROP) {
				t.Fatalf("expected verdict Drop for true comparison, got %v", v)
			}
		})
	}
}

// mockPacketOwner implements PacketOwner for testing.
type mockPacketOwner struct {
	uid uint32
	gid uint32
}

// KUID returns the UID of the mock packet owner.
func (m mockPacketOwner) KUID() uint32 {
	return m.uid
}

// KGID returns the GID of the mock packet owner.
func (m mockPacketOwner) KGID() uint32 {
	return m.gid
}

// TestEvaluateMetaLoad tests that the Meta Load operation correctly loads
// the specific meta data into the destination register.
// The nft binary commands used to generate these are stated above each test.
// All commands should be preceded by nft --debug=netlink.
// Note: Relies on expected behavior of the Comparison operation.
// Note: Does all comparisons in multiples of 4 bytes.
// TODO(b/339691111): Add tests for VLAN, ARP, ICMP, ICMPv6, IGMP, UDP headers.
func TestEvaluateMetaLoad(t *testing.T) {
	// Initializes testing packet.
	tcid := 0x05
	pktSize := header.IPv6MinimumSize + header.TCPMinimumSize
	ipv6Fields := arbitraryIPv6Fields()
	ipv6Fields.TrafficClass = uint8(tcid)
	tcpFields := arbitraryTCPFields()
	pkt := makeIPv6TCPPacket(pktSize, ipv6Fields, tcpFields)
	pkt.Owner = &mockPacketOwner{arbitrarySKUID, arbitrarySKGID}

	// Sets up a fake clock (now = UnixEpoch) and dependent time/random fields.
	fakeClock := faketime.NewManualClock()
	now := fakeClock.Now()
	timeNS := now.UnixNano()
	timeDay := now.Weekday()
	timeHour := now.Hour()*3600 + now.Minute()*60 + now.Second()
	fixedRNG := rand.RNGFrom(&fixedReader{})
	seededRandUint32 := fixedRNG.Uint32() // fixes rng

	for _, test := range []struct {
		tname string
		pkt   *stack.PacketBuffer
		op1   operation // Meta Load operation to test.
		op2   operation // Comparison operation to check result data in register.
		// Note: op2 should be nil if expecting a break during evaluation.
	}{
		{ // cmd: add rule ip6 tab ch meta length 60
			tname: "meta load len test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_LEN, linux.NFT_REG_2),
			op2: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_EQ,
				binary.NativeEndian.AppendUint32(nil, uint32(pktSize))),
		},
		{ // cmd: add rule ip6 tab ch meta protocol 0x86dd
			tname: "meta load protocol test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_PROTOCOL, linux.NFT_REG_3),
			op2: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_EQ,
				append(numToBE(int(header.IPv6ProtocolNumber), 2), 0, 0)),
		},
		{ // meta nfproto is only useful in the inet family
			// cmd: add rule inet tab ch meta nfproto 0x0a
			tname: "meta load nfproto test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_NFPROTO, linux.NFT_REG_4),
			op2: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_EQ,
				[]byte{AfProtocol(stack.Inet), 0, 0, 0}),
		},
		{ // cmd: add rule ip6 tab ch meta l4proto 0x6
			tname: "meta load l4proto test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_L4PROTO, linux.NFT_REG32_00),
			op2: mustCreateComparison(t, linux.NFT_REG32_00, linux.NFT_CMP_EQ,
				[]byte{uint8(tcpTransportProtocol), 0, 0, 0}),
		},
		{ // cmd: add rule ip6 tab ch skuid 0x020304
			tname: "meta load skuid test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_SKUID, linux.NFT_REG32_02),
			op2: mustCreateComparison(t, linux.NFT_REG32_02, linux.NFT_CMP_EQ,
				binary.NativeEndian.AppendUint32(nil, arbitrarySKUID)),
		},
		{ // cmd: add rule ip6 tab ch skgid 45668
			tname: "meta load skgid test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_SKGID, linux.NFT_REG32_03),
			op2: mustCreateComparison(t, linux.NFT_REG32_03, linux.NFT_CMP_EQ,
				binary.NativeEndian.AppendUint32(nil, arbitrarySKGID)),
		},
		{ // cmd: add rule ip6 tab ch rtclassid 0x05
			tname: "meta load rtclassid test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_RTCLASSID, linux.NFT_REG32_04),
			op2: mustCreateComparison(t, linux.NFT_REG32_04, linux.NFT_CMP_EQ,
				binary.NativeEndian.AppendUint32(nil, uint32(tcid))),
		},
		{ // cmd: add rule ip6 tab ch pkttype 2
			tname: "meta load pkttype test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_PKTTYPE, linux.NFT_REG32_05),
			op2: mustCreateComparison(t, linux.NFT_REG32_05, linux.NFT_CMP_EQ,
				[]byte{uint8(arbitraryPktType), 0, 0, 0}),
		},
		{ // cmd: add rule ip6 tab ch meta random 4059586549
			tname: "meta load prandom test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_PRANDOM, linux.NFT_REG32_01),
			op2: mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_EQ,
				numToBE(int(seededRandUint32), 4)),
		},
		{ // cmd: add rule ip6 tab ch time "1970-01-01 00:00:00"
			tname: "meta load time at unix epoch test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_TIME_NS, linux.NFT_REG_3),
			op2: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_EQ,
				binary.NativeEndian.AppendUint64(nil, uint64(timeNS))),
		},
		{ // cmd: add rule ip6 tab ch day Thursday
			tname: "meta load day test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_TIME_DAY, linux.NFT_REG32_15),
			op2: mustCreateComparison(t, linux.NFT_REG32_15, linux.NFT_CMP_EQ,
				[]byte{uint8(timeDay), 0, 0, 0}),
		},
		{ // cmd: add rule inet tab ch hour 0x01020304
			tname: "meta load hour test",
			pkt:   pkt,
			op1:   mustCreateMetaLoad(t, linux.NFT_META_TIME_HOUR, linux.NFT_REG32_14),
			op2: mustCreateComparison(t, linux.NFT_REG32_14, linux.NFT_CMP_EQ,
				binary.NativeEndian.AppendUint32(nil, uint32(timeHour))),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a base chain and fake manual clock.
			// Using Manual Clock sets time.Now to Unix Epoch which fixes rng seed!
			nf := NewNFTables(fakeClock, rand.RNGFrom(&fixedReader{}))

			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Adds drop operation. Will be final verdict if all comparisons are true.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation.
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, test.pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}

			// Checks for final verdict.
			if test.op2 == nil {
				// If no comparison operation is set, then payload load should break,
				// resulting in Accept as the default policy verdict.
				if v.Code != VC(linux.NF_ACCEPT) {
					t.Fatalf("expected verdict Accept for break during evaluation, got %v", v)
				}
			} else {
				// If a comparison operation is set, both payload load and comparison
				// should succeed, resulting in Drop as the final verdict.
				if v.Code != VC(linux.NF_DROP) {
					t.Fatalf("expected verdict Drop for true comparison, got %v", v)
				}
			}
		})
	}
}

// TestEvaluateMetaSet tests that the Meta Set operation correctly sets specific
// packet meta data to the value in the source register.
func TestEvaluateMetaSet(t *testing.T) {
	// Packet type to set anc test for.
	testPktType := tcpip.PacketMulticast
	for _, test := range []struct {
		tname  string
		pkt    *stack.PacketBuffer
		outPkt *stack.PacketBuffer
		op1    operation // Immediate operation to load source register.
		op2    operation // Meta set operation to test.
	}{
		// cmd: nft --debug=netlink add rule ip tab ch meta pkttype set 34
		{
			tname: "meta set pkttype 4-byte reg test",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				pkt := makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields())
				pkt.PktType = testPktType
				return pkt
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG32_06, newBytesData([]byte{uint8(testPktType)})),
			op2: mustCreateMetaSet(t, linux.NFT_META_PKTTYPE, linux.NFT_REG32_06),
		},
		{
			tname: "meta set pkttype 16-byte reg test",
			pkt:   makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields()),
			outPkt: func() *stack.PacketBuffer {
				pkt := makeIPv4Packet(header.IPv4MinimumSize, arbitraryIPv4Fields())
				pkt.PktType = testPktType
				return pkt
			}(),
			op1: mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{uint8(testPktType)})),
			op2: mustCreateMetaSet(t, linux.NFT_META_PKTTYPE, linux.NFT_REG_3),
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a single table, chain, and rule.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			rule := &Rule{}

			// Adds testing operations.
			if test.op1 != nil {
				rule.addOperation(test.op1)
			}
			if test.op2 != nil {
				rule.addOperation(test.op2)
			}

			// Adds drop operation, to be final verdict if evaluation is successful.
			rule.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))

			// Registers the rule to the base chain.
			if err := bc.RegisterRule(rule, -1); err != nil {
				t.Fatalf("unexpected error for RegisterRule: %v", err)
			}

			// Runs evaluation.
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, test.pkt)
			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}

			// Evaluation should be successful and result in Drop verdict.
			if v.Code != VC(linux.NF_DROP) {
				t.Fatalf("expected verdict Drop for successful evaluation, got %v", v)
			}

			// Checks if the packet are equal.
			checkPacketEquality(t, test.outPkt, test.pkt)
		})
	}
}

// TestLoopCheckOnRegisterAndUnregister tests the loop checking and accompanying
// logic on registering and unregistering rules.
func TestLoopCheckOnRegisterAndUnregister(t *testing.T) {
	for _, test := range []struct {
		tname     string
		chains    map[string]*Chain
		verdict   stack.NFVerdict
		shouldErr bool
	}{
		{
			tname: "jump to non-existent chain",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "non_existent_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "goto to non-existent chain",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "non_existent_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "jump to itself",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "goto to itself",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 2-chain loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "2-chain loop with entry point outside loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 3-chain loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "3-chain loop with entry point 2 points outside loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain4"}))},
					}},
				},
				"aux_chain4": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 4-chain loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 5-chain loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			//     0
			//  	/ \
			//   v   v
			//   1 <- 2 <-> 3
			tname: "complex 2-3 loop",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{{
						ops: []operation{
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
						},
					}},
				},
				"aux_chain": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)}))},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"})),
						},
					}},
				},
				"aux_chain3": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple loop amongst other rules and operations",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0, 1, 2, 3}))}},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG32_14, newBytesData([]byte{0, 1, 2, 3}))}},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))}},
					},
				},
				"aux_chain": {
					rules: []*Rule{{
						ops: []operation{
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"})),
						},
					}},
				},
				"aux_chain2": {
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": {
					rules: []*Rule{
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0, 1, 2, 3}))}},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG32_14, newBytesData([]byte{0, 1, 2, 3}))}},
						{ops: []operation{
							mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain"})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
						}},
					},
				},
			},
			shouldErr: true,
		},
		{
			tname: "base chain jump to 3 other chains",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						{
							ops: []operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
							},
						},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))}},
					},
				},
				"aux_chain": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain2": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain3": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
			},
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname: "base chain jump to 3 other chains with last chain dropping",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						{
							ops: []operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
							},
						},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))}},
					},
				},
				"aux_chain": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain2": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain3": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)}))},
					}},
				},
			},
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)}, // from last chain
		},
		{
			tname: "base chain jump to 3 other chains with last rule in base chain dropping",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						{
							ops: []operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
							},
						},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))}},
						{ops: []operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)}))}},
					},
				},
				"aux_chain": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain2": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain3": {
					comment: "strictly target",
					rules: []*Rule{{
						ops: []operation{mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
			},
			verdict: stack.NFVerdict{Code: VC(linux.NF_DROP)}, // from last rule in base chain
		},
		{
			tname: "jump to the same chain",
			chains: map[string]*Chain{
				"base_chain": {
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						{
							ops: []operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
							},
						},
					},
				},
				"aux_chain": {
					comment: "strictly target",
					rules:   []*Rule{{}},
				},
			},
			verdict: stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object based on test struct.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			// Creates all chains in the test struct first. This is necessary so the
			// loop checking sees the target chains exist (otherwise it would error).
			for chainName, chainInit := range test.chains {
				tab.AddChain(chainName, chainInit.GetBaseChainInfo(), chainInit.GetComment(), false)
			}
			if len(test.chains) != tab.ChainCount() {
				t.Fatalf("not all chains added to table")
			}
			// Registers all rules to all chains in the test struct.
			for chainName, chainInit := range test.chains {
				chain, err := nf.GetChain(tab.GetAddressFamily(), tab.GetName(), chainName)
				if err != nil {
					t.Fatalf("unexpected error for GetChain: %v", err)
				}
				for _, rule := range chainInit.rules {
					// Note: this is where the loop checking is triggered.
					if err := chain.RegisterRule(rule, -1); err != nil {
						if !test.shouldErr {
							t.Fatalf("unexpected error for RegisterRule: %v", err)
						}
						return
					}
					// Checks that the chain was assigned to the rule.
					if rule.chain == nil {
						t.Fatalf("chain is not assigned to rule after RegisterRule")
					}
				}
				if chainInit.RuleCount() != chain.RuleCount() {
					t.Fatalf("not all rules added to chain")
				}
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				if test.verdict.ChainName != "error" {
					t.Fatalf("unexpected error for EvaluateHook: %v", err)
				}
			}
			if v.Code != test.verdict.Code {
				t.Fatalf("expected verdict %v, got %v", test.verdict, v)
			}

			// Unregisters all rules from all chains and checks that the chain is
			// unassigned from the rule.
			for chainName, chainInit := range test.chains {
				chain, err := nf.GetChain(tab.GetAddressFamily(), tab.GetName(), chainName)
				if err != nil {
					t.Fatalf("unexpected error for GetChain: %v", err)
				}
				for rIdx := chainInit.RuleCount() - 1; rIdx >= 0; rIdx-- {
					rule, err := chain.UnregisterRuleByIndex(rIdx)
					if err != nil {
						t.Fatalf("unexpected error for UnregisterRule: %v", err)
					}
					if rule != chainInit.rules[rIdx] {
						t.Fatalf("rule returned by UnregisterRule does not match previously registered rule")
					}
					if rule.chain != nil {
						t.Fatalf("chain is not unassigned from rule after UnregisterRule")
					}
				}
				if chain.RuleCount() != 0 {
					t.Fatalf("not all rules removed from chain")
				}
			}
		})
	}
}

// TestMaxNestedJumps tests the limit on nested jumps (no limit for gotos).
func TestMaxNestedJumps(t *testing.T) {
	for _, test := range []struct {
		tname         string
		useJumpOp     bool
		numberOfJumps int
		verdict       stack.NFVerdict // ChainName is set to "error" if an error is expected
	}{
		{
			tname:         "nested jump limit reached with jumps",
			useJumpOp:     true,
			numberOfJumps: nestedJumpLimit,
			verdict:       stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:         "nested jump limit reached with gotos",
			useJumpOp:     false,
			numberOfJumps: nestedJumpLimit,
			verdict:       stack.NFVerdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:         "nested jump limit exceeded with jumps",
			useJumpOp:     true,
			numberOfJumps: nestedJumpLimit + 1,
			verdict:       stack.NFVerdict{ChainName: "error"},
		},
		{
			tname:         "nested jump limit exceeded with gotos",
			useJumpOp:     false,
			numberOfJumps: nestedJumpLimit + 1,
			verdict:       stack.NFVerdict{Code: VC(linux.NF_DROP)}, // limit only for jumps
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up chains of nested jumps or gotos.
			nf := newNFTablesStd()
			tab, err := nf.AddTable(arbitraryFamily, "test", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			for i := test.numberOfJumps - 1; i >= 0; i-- {
				name := fmt.Sprintf("chain %d", i)
				c, err := tab.AddChain(name, nil, "test chain", false)
				if i == 0 {
					c.SetBaseChainInfo(arbitraryInfoPolicyAccept)
				}
				if err != nil {
					t.Fatalf("unexpected error for AddChain: %v", err)
				}
				r := &Rule{}
				if i == test.numberOfJumps-1 {
					err = r.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})))
				} else {
					targetName := fmt.Sprintf("chain %d", i+1)
					code := VC(linux.NFT_JUMP)
					if !test.useJumpOp {
						code = VC(linux.NFT_GOTO)
					}
					err = r.addOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: code, ChainName: targetName})))
				}
				if err != nil {
					t.Fatalf("unexpected error for AddOperation: %v", err)
				}
				if err := c.RegisterRule(r, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule: %v", err)
				}
			}

			// Runs evaluation and checks verdict.
			pkt := makeArbitraryPacket(arbitraryReservedHeaderBytes)
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				if test.verdict.ChainName != "error" {
					t.Fatalf("unexpected error for EvaluateHook: %v", err)
				}
			}
			if v.Code != test.verdict.Code {
				t.Fatalf("expected verdict %v, got %v", test.verdict, v)
			}
		})
	}
}

// checkPacketEquality checks that the given packets are equal for all fields
// and data relevant to our testing. This is not an exhaustive check.
func checkPacketEquality(t *testing.T, expected, actual *stack.PacketBuffer) {
	if expected.PktType != actual.PktType {
		t.Fatalf("expected packet type %d for resulting packet, got %d", int(expected.PktType), int(actual.PktType))
	}

	// Compares checksums first for the expected and actual packet.
	if expected.NetworkProtocolNumber != actual.NetworkProtocolNumber {
		t.Fatalf("expected network protocol number %d for resulting packet, got %d", expected.NetworkProtocolNumber, actual.NetworkProtocolNumber)
	}
	if actualHasNetwork, expectedHasNetwork := actual.NetworkHeader().View() != nil, expected.NetworkHeader().View() != nil; actualHasNetwork != expectedHasNetwork {
		t.Fatalf("expected network header is present to be %t for resulting packet, got %v", actualHasNetwork, expectedHasNetwork)
	}
	if actual.NetworkHeader().View() != nil && expected.Network().Checksum() != actual.Network().Checksum() {
		t.Fatalf("expected network checksum %d for resulting packet, got %d", expected.Network().Checksum(), actual.Network().Checksum())
	}
	if actual.TransportProtocolNumber != expected.TransportProtocolNumber {
		t.Fatalf("expected transport protocol number %d for resulting packet, got %d", expected.TransportProtocolNumber, actual.TransportProtocolNumber)
	}
	if actual.TransportProtocolNumber != 0 {
		var transport header.Transport
		var transportExpected header.Transport
		switch tBytes, tOutBytes := actual.TransportHeader().Slice(), expected.TransportHeader().Slice(); actual.TransportProtocolNumber {
		case header.TCPProtocolNumber:
			transport = header.TCP(tBytes)
			transportExpected = header.TCP(tOutBytes)
		case header.UDPProtocolNumber:
			transport = header.UDP(tBytes)
			transportExpected = header.UDP(tOutBytes)
		case header.ICMPv4ProtocolNumber:
			transport = header.ICMPv4(tBytes)
			transportExpected = header.ICMPv4(tOutBytes)
		case header.ICMPv6ProtocolNumber:
			transport = header.ICMPv6(tBytes)
			transportExpected = header.ICMPv6(tOutBytes)
		case header.IGMPProtocolNumber:
			transport = header.IGMP(tBytes)
			transportExpected = header.IGMP(tOutBytes)
		}
		if transport != nil && transport.Checksum() != transportExpected.Checksum() {
			t.Fatalf("expected transport checksum %d for resulting packet, got %d", transport.Checksum(), transportExpected.Checksum())
		}
	}

	// Compares raw packet data in bytes for resulting and expected packet.
	actualSlices := actual.AsSlices()
	expectedSlices := expected.AsSlices()
	if len(actualSlices) != len(expectedSlices) {
		t.Fatalf("expected %d slices of data for the resulting packet, got %d", len(expectedSlices), len(actualSlices))
	}
	for i := range actualSlices {
		if !slices.Equal(actualSlices[i], expectedSlices[i]) {
			t.Fatalf("packet data does not match expected packet data (for slice %d)", i)
		}
	}
}

// numToBE converts an n-byte int to Big Endian where n is in [1, 8].
// Assumes the given number can be represented in n bytes.
func numToBE(v int, n int) []byte {
	if n > 8 {
		panic("cannot support more than 8 bytes")
	}
	// Gets 8-byte slice Big Endian representation of the number.
	be64 := binary.BigEndian.AppendUint64(nil, uint64(v))
	// Returns last n bytes as the n-byte Big Endian representation.
	return be64[8-n:]
}

// packetResultString compares 2 packets by equality and returns a string
// representation.
func packetResultString(initial, final *stack.PacketBuffer) string {
	if final == nil {
		return "nil"
	}
	if reflect.DeepEqual(final, initial) {
		return "unmodified"
	}
	return "modified"
}

// newNFTablesStd creates a new NFTables object w/ a standard clock for testing.
func newNFTablesStd() *NFTables {
	stdClock := tcpip.NewStdClock()
	fixedRNG := rand.RNGFrom(&fixedReader{})
	return NewNFTables(stdClock, fixedRNG)
}

// mustCreateImmediate wraps the newImmediate function for brevity.
func mustCreateImmediate(t *testing.T, dreg uint8, data registerData) *immediate {
	imm, err := newImmediate(dreg, data)
	if err != nil {
		t.Fatalf("failed to create immediate: %v", err)
	}
	return imm
}

// mustCreateComparison wraps the newComparison function for brevity.
func mustCreateComparison(t *testing.T, sreg uint8, cop int, data []byte) *comparison {
	cmp, err := newComparison(sreg, cop, data)
	if err != nil {
		t.Fatalf("failed to create comparison: %v", err)
	}
	return cmp
}

// mustCreateRanged wraps the newRanged function for brevity.
func mustCreateRanged(t *testing.T, sreg uint8, rop int, low, high []byte) *ranged {
	rng, err := newRanged(sreg, rop, low, high)
	if err != nil {
		t.Fatalf("failed to create ranged: %v", err)
	}
	return rng
}

// mustCreatePayloadLoad wraps the newPayloadLoad function for brevity.
func mustCreatePayloadLoad(t *testing.T, base payloadBase, offset, len, dreg uint8) *payloadLoad {
	pdload, err := newPayloadLoad(base, offset, len, dreg)
	if err != nil {
		t.Fatalf("failed to create payload load: %v", err)
	}
	return pdload
}

// mustCreatePayloadSet wraps the newPayloadSet function for brevity.
func mustCreatePayloadSet(t *testing.T, base payloadBase, offset uint8, len uint8, sreg uint8, csumType uint8, csumOff uint8, csumFlags uint8) *payloadSet {
	pdset, err := newPayloadSet(base, offset, len, sreg, csumType, csumOff, csumFlags)
	if err != nil {
		t.Fatalf("failed to create payload set: %v", err)
	}
	return pdset
}

// mustCreateBitwiseBool wraps the newBitwiseBool function for brevity.
func mustCreateBitwiseBool(t *testing.T, sreg, dreg uint8, mask, xor []byte) *bitwise {
	bit, err := newBitwiseBool(sreg, dreg, mask, xor)
	if err != nil {
		t.Fatalf("failed to create bitwise bool: %v", err)
	}
	return bit
}

// mustCreateBitwiseShift wraps the newBitwiseShift function for brevity.
func mustCreateBitwiseShift(t *testing.T, sreg, dreg, blen uint8, shift uint32, right bool) *bitwise {
	bit, err := newBitwiseShift(sreg, dreg, blen, shift, right)
	if err != nil {
		t.Fatalf("failed to create bitwise shift: %v", err)
	}
	return bit
}

// mustCreateRoute wraps the newRoute function for brevity.
func mustCreateRoute(t *testing.T, key routeKey, dreg uint8) *route {
	rt, err := newRoute(key, dreg)
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}
	return rt
}

// mustCreateByteorder wraps the newByteorder function for brevity.
func mustCreateByteorder(t *testing.T, sreg, dreg uint8, bop byteorderOp, blen, size uint8) *byteorder {
	order, err := newByteorder(sreg, dreg, bop, blen, size)
	if err != nil {
		t.Fatalf("failed to create byteorder: %v", err)
	}
	return order
}

// mustCreateMetaLoad wraps the newMetaLoad function for brevity.
func mustCreateMetaLoad(t *testing.T, key metaKey, dreg uint8) *metaLoad {
	mtload, err := newMetaLoad(key, dreg)
	if err != nil {
		t.Fatalf("failed to create meta load: %v", err)
	}
	return mtload
}

// mustCreateMetaSet wraps the newMetaSet function for brevity.
func mustCreateMetaSet(t *testing.T, key metaKey, sreg uint8) *metaSet {
	mtset, err := newMetaSet(key, sreg)
	if err != nil {
		t.Fatalf("failed to create meta set: %v", err)
	}
	return mtset
}

// A fixedReader sets all bytes to the same value (1) when Read is called.
//
// It is used to make the RNG deterministic for testing, i.e. it's really
// really bad at being an RNG.
type fixedReader struct{}

// Read implements io.Reader.Read.
func (*fixedReader) Read(buf []byte) (int, error) {
	for i := range len(buf) {
		buf[i] = 1
	}
	return len(buf), nil
}
