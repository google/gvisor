// Copyright 2022 The gVisor Authors.
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

package context

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	v4MappedAddrPrefix = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"

	// StackPort is the port TestFlow uses with StackAddr.
	StackPort = 1234

	// TestPort is the port TestFlow uses with TestAddr.
	TestPort = 4096

	// StackAddr is the IPv4 address assigned to the stack's NIC and is used by
	// TestFlow as the local address.
	StackAddr = "\x0a\x00\x00\x01"

	// StackV4MappedAddr is the IPv4-mapped IPv6 StackAddr.
	StackV4MappedAddr = v4MappedAddrPrefix + StackAddr

	// TestAddr is the IPv4 address used by TestFlow as the remote address.
	TestAddr = "\x0a\x00\x00\x02"

	// TestV4MappedAddr is the IPv4-mapped IPv6 TestAddr.
	TestV4MappedAddr = v4MappedAddrPrefix + TestAddr

	// MulticastAddr is the IPv4 multicast address used by IPv4 multicast
	// TestFlow.
	MulticastAddr = "\xe8\x2b\xd3\xea"

	// MulticastV4MappedAddr is the IPv4-mapped IPv6 MulticastAddr.
	MulticastV4MappedAddr = v4MappedAddrPrefix + MulticastAddr

	// BroadcastAddr is the IPv4 broadcast address.
	BroadcastAddr = header.IPv4Broadcast

	// BroadcastV4MappedAddr is the IPv4-mapped IPv6 BroadcastAddr.
	BroadcastV4MappedAddr = v4MappedAddrPrefix + BroadcastAddr

	// V4MappedWildcardAddr is the IPv4-mapped IPv6 wildcard (any) address.
	V4MappedWildcardAddr = v4MappedAddrPrefix + "\x00\x00\x00\x00"

	// StackV6Addr is the IPv6 address assigned to the stack's NIC and is used by
	// TestFlow as the local address.
	StackV6Addr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

	// TestV6Addr is the IPv6 address used by TestFlow as the remote address.
	TestV6Addr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

	// MulticastV6Addr is the IPv6 multicast address used by IPv6 multicast
	// TestFlow.
	MulticastV6Addr = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

// Header4Tuple stores the 4-tuple {src-IP, src-port, dst-IP, dst-port} used in
// a packet header. These values are used to populate a header or verify one.
// Note that because they are used in packet headers, the addresses are never in
// a V4-mapped format.
type Header4Tuple struct {
	Src tcpip.FullAddress
	Dst tcpip.FullAddress
}

// TestFlow implements a helper type used for sending and receiving test
// packets. A given test TestFlow value defines 1) the socket endpoint used for
// the test and 2) the type of packet send or received on the endpoint. E.g., a
// MulticastV6Only TestFlow is a IPv6 multicast packet passing through a V6-only
// endpoint. The type provides helper methods to characterize the TestFlow
// (e.g., IsV4) as well as return a proper Header4Tuple for it.
type TestFlow int

const (
	_ TestFlow = iota

	// UnicastV4 is IPv4 unicast on an IPv4 socket
	UnicastV4

	// UnicastV4in6 is IPv4-mapped IPv6 unicast on an IPv6 dual socket
	UnicastV4in6

	// UnicastV6 is IPv6 unicast on an IPv6 socket
	UnicastV6

	// UnicastV6Only is IPv6 unicast on an IPv6-only socket
	UnicastV6Only

	// MulticastV4 is IPv4 multicast on an IPv4 socket
	MulticastV4

	// MulticastV4in6 is IPv4-mapped IPv6 multicast on an IPv6 dual socket
	MulticastV4in6

	// MulticastV6 is IPv6 multicast on an IPv6 socket
	MulticastV6

	// MulticastV6Only IPv6 multicast on an IPv6-only socket
	MulticastV6Only

	// Broadcast is IPv4 broadcast on an IPv4 socket
	Broadcast

	// BroadcastIn6 is IPv4-mapped IPv6 broadcast on an IPv6 dual socket
	BroadcastIn6

	// ReverseMulticastV4 is IPv4 multicast src. Must fail.
	ReverseMulticastV4

	// ReverseMulticastV6 is IPv6 multicast src. Must fail.
	ReverseMulticastV6
)

// String implements fmt.Stringer interface.
func (flow TestFlow) String() string {
	switch flow {
	case UnicastV4:
		return "UnicastV4"
	case UnicastV6:
		return "UnicastV6"
	case UnicastV6Only:
		return "UnicastV6Only"
	case UnicastV4in6:
		return "UnicastV4in6"
	case MulticastV4:
		return "MulticastV4"
	case MulticastV6:
		return "MulticastV6"
	case MulticastV6Only:
		return "MulticastV6Only"
	case MulticastV4in6:
		return "MulticastV4in6"
	case Broadcast:
		return "Broadcast"
	case BroadcastIn6:
		return "BroadcastIn6"
	case ReverseMulticastV4:
		return "ReverseMulticastV4"
	case ReverseMulticastV6:
		return "ReverseMulticastV6"
	default:
		return "Unknown"
	}
}

// PacketDirection specifies the direction of a TestFlow.
type PacketDirection int

const (
	_ PacketDirection = iota

	// Incoming indicates the direction from Test*Addr to Stack*Addr.
	Incoming

	// Outgoing indicates the direction from Test*Addr to Stack*Addr.
	Outgoing
)

// MakeHeader4Tuple returns the Header4Tuple for the given TestFlow and direction. Note
// that the tuple contains no mapped addresses as those only exist at the socket
// level but not at the packet header level.
func (flow TestFlow) MakeHeader4Tuple(direction PacketDirection) Header4Tuple {
	var h Header4Tuple
	if flow.IsV4() {
		switch direction {
		case Outgoing:
			h = Header4Tuple{
				Src: tcpip.FullAddress{Addr: StackAddr, Port: StackPort},
				Dst: tcpip.FullAddress{Addr: TestAddr, Port: TestPort},
			}
		case Incoming:
			h = Header4Tuple{
				Src: tcpip.FullAddress{Addr: TestAddr, Port: TestPort},
				Dst: tcpip.FullAddress{Addr: StackAddr, Port: StackPort},
			}
		default:
			panic(fmt.Sprintf("unknown direction %d", direction))
		}

		if flow.IsMulticast() {
			h.Dst.Addr = MulticastAddr
		} else if flow.isBroadcast() {
			h.Dst.Addr = BroadcastAddr
		}
	} else { // IPv6
		switch direction {
		case Outgoing:
			h = Header4Tuple{
				Src: tcpip.FullAddress{Addr: StackV6Addr, Port: StackPort},
				Dst: tcpip.FullAddress{Addr: TestV6Addr, Port: TestPort},
			}
		case Incoming:
			h = Header4Tuple{
				Src: tcpip.FullAddress{Addr: TestV6Addr, Port: TestPort},
				Dst: tcpip.FullAddress{Addr: StackV6Addr, Port: StackPort},
			}
		default:
			panic(fmt.Sprintf("unknown direction %d", direction))
		}

		if flow.IsMulticast() {
			h.Dst.Addr = MulticastV6Addr
		}
	}

	if flow.isReverseMulticast() {
		h.Src.Addr = flow.GetMulticastAddr()
	}

	return h
}

// GetMulticastAddr returns the multicast address of a TestFlow.
func (flow TestFlow) GetMulticastAddr() tcpip.Address {
	if flow.IsV4() {
		return MulticastAddr
	}
	return MulticastV6Addr
}

// MapAddrIfApplicable converts the given IPv4 address into its V4-mapped
// version if it is applicable to the TestFlow.
func (flow TestFlow) MapAddrIfApplicable(v4Addr tcpip.Address) tcpip.Address {
	if flow.isMapped() {
		return v4MappedAddrPrefix + v4Addr
	}
	return v4Addr
}

// NetProto returns the network protocol of a TestFlow.
func (flow TestFlow) NetProto() tcpip.NetworkProtocolNumber {
	if flow.IsV4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// SockProto returns the network protocol number a socket must be configured
// with to support a given TestFlow.
func (flow TestFlow) SockProto() tcpip.NetworkProtocolNumber {
	switch flow {
	case UnicastV4in6, UnicastV6, UnicastV6Only, MulticastV4in6, MulticastV6, MulticastV6Only, BroadcastIn6, ReverseMulticastV6:
		return ipv6.ProtocolNumber
	case UnicastV4, MulticastV4, Broadcast, ReverseMulticastV4:
		return ipv4.ProtocolNumber
	default:
		panic(fmt.Sprintf("invalid TestFlow given: %d", flow))
	}
}

// CheckerFn returns the correct network checker for the current TestFlow.
func (flow TestFlow) CheckerFn() func(*testing.T, *bufferv2.View, ...checker.NetworkChecker) {
	if flow.IsV4() {
		return checker.IPv4
	}
	return checker.IPv6
}

// IsV4 returns true for IPv4 TestFlow's.
func (flow TestFlow) IsV4() bool {
	return flow.SockProto() == ipv4.ProtocolNumber || flow.isMapped()
}

// IsV6 returns true for IPv6 TestFlow's.
func (flow TestFlow) IsV6() bool { return !flow.IsV4() }

func (flow TestFlow) isV6Only() bool {
	switch flow {
	case UnicastV6Only, MulticastV6Only:
		return true
	case UnicastV4, UnicastV4in6, UnicastV6, MulticastV4, MulticastV4in6, MulticastV6, Broadcast, BroadcastIn6, ReverseMulticastV4, ReverseMulticastV6:
		return false
	default:
		panic(fmt.Sprintf("invalid TestFlow given: %d", flow))
	}
}

// IsMulticast returns true if the TestFlow is multicast.
func (flow TestFlow) IsMulticast() bool {
	switch flow {
	case MulticastV4, MulticastV4in6, MulticastV6, MulticastV6Only:
		return true
	case UnicastV4, UnicastV4in6, UnicastV6, UnicastV6Only, Broadcast, BroadcastIn6, ReverseMulticastV4, ReverseMulticastV6:
		return false
	default:
		panic(fmt.Sprintf("invalid TestFlow given: %d", flow))
	}
}

func (flow TestFlow) isBroadcast() bool {
	switch flow {
	case Broadcast, BroadcastIn6:
		return true
	case UnicastV4, UnicastV4in6, UnicastV6, UnicastV6Only, MulticastV4, MulticastV4in6, MulticastV6, MulticastV6Only, ReverseMulticastV4, ReverseMulticastV6:
		return false
	default:
		panic(fmt.Sprintf("invalid TestFlow given: %d", flow))
	}
}

func (flow TestFlow) isMapped() bool {
	switch flow {
	case UnicastV4in6, MulticastV4in6, BroadcastIn6:
		return true
	case UnicastV4, UnicastV6, UnicastV6Only, MulticastV4, MulticastV6, MulticastV6Only, Broadcast, ReverseMulticastV4, ReverseMulticastV6:
		return false
	default:
		panic(fmt.Sprintf("invalid TestFlow given: %d", flow))
	}
}

func (flow TestFlow) isReverseMulticast() bool {
	switch flow {
	case ReverseMulticastV4, ReverseMulticastV6:
		return true
	default:
		return false
	}
}

// BuildV4UDPPacket builds an IPv4 UDP packet.
func BuildV4UDPPacket(payload []byte, h Header4Tuple, tos, ttl uint8, badChecksum bool) []byte {
	// Allocate a buffer for data and headers.
	buf := make([]byte, header.UDPMinimumSize+header.IPv4MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TOS:         tos,
		TotalLength: uint16(len(buf)),
		TTL:         ttl,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     h.Src.Addr,
		DstAddr:     h.Dst.Addr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.Src.Port,
		DstPort: h.Dst.Port,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, h.Src.Addr, h.Dst.Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	if badChecksum {
		// Invalidate the UDP header checksum field, taking care to avoid overflow
		// to zero, which would disable checksum validation.
		for {
			u.SetChecksum(u.Checksum() + 1)
			if u.Checksum() != 0 {
				break
			}
		}
	}

	return buf
}

// BuildV6UDPPacket builds an IPv6 UDP packet.
func BuildV6UDPPacket(payload []byte, h Header4Tuple, tclass, hoplimit uint8, badChecksum bool) []byte {
	// Allocate a buffer for data and headers.
	buf := make([]byte, header.UDPMinimumSize+header.IPv6MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		TrafficClass:      tclass,
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          hoplimit,
		SrcAddr:           h.Src.Addr,
		DstAddr:           h.Dst.Addr,
	})

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.Src.Port,
		DstPort: h.Dst.Port,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, h.Src.Addr, h.Dst.Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	if badChecksum {
		// Invalidate the UDP header checksum field (Unlike IPv4, zero is a valid
		// checksum value for IPv6 so no need to avoid it).
		u := header.UDP(buf[header.IPv6MinimumSize:])
		u.SetChecksum(u.Checksum() + 1)
	}

	return buf
}

// BuildUDPPacket builds an IPv4 or IPv6 UDP packet, depending on the specified
// TestFlow.
func BuildUDPPacket(payload []byte, flow TestFlow, direction PacketDirection, tosOrTclass, ttlOrHopLimit uint8, badChecksum bool) []byte {
	h := flow.MakeHeader4Tuple(direction)
	if flow.IsV4() {
		return BuildV4UDPPacket(payload, h, tosOrTclass, ttlOrHopLimit, badChecksum)
	}
	return BuildV6UDPPacket(payload, h, tosOrTclass, ttlOrHopLimit, badChecksum)
}
