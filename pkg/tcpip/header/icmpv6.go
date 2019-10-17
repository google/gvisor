// Copyright 2018 The gVisor Authors.
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

package header

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// ICMPv6 represents an ICMPv6 header stored in a byte array.
type ICMPv6 []byte

const (
	// ICMPv6HeaderSize is the size of the ICMPv6 header. That is, the
	// sum of the size of the ICMPv6 Type, Code and Checksum fields, as
	// per RFC 4443 section 2.1. After the ICMPv6 header, the ICMPv6
	// message body begins.
	ICMPv6HeaderSize = 4

	// ICMPv6MinimumSize is the minimum size of a valid ICMP packet.
	ICMPv6MinimumSize = 8

	// ICMPv6PayloadOffset is the offset of the payload in an
	// ICMP packet.
	ICMPv6PayloadOffset = 8

	// ICMPv6ProtocolNumber is the ICMP transport protocol number.
	ICMPv6ProtocolNumber tcpip.TransportProtocolNumber = 58

	// ICMPv6NeighborSolicitMinimumSize is the minimum size of a
	// neighbor solicitation packet.
	ICMPv6NeighborSolicitMinimumSize = ICMPv6HeaderSize + NDPNSMinimumSize

	// ICMPv6NeighborAdvertMinimumSize is the minimum size of a
	// neighbor advertisement packet.
	ICMPv6NeighborAdvertMinimumSize = ICMPv6HeaderSize + NDPNAMinimumSize

	// ICMPv6NeighborAdvertSize is size of a neighbor advertisement
	// including the NDP Target Link Layer option for an Ethernet
	// address.
	ICMPv6NeighborAdvertSize = ICMPv6HeaderSize + NDPNAMinimumSize + ndpTargetEthernetLinkLayerAddressSize

	// ICMPv6EchoMinimumSize is the minimum size of a valid ICMP echo packet.
	ICMPv6EchoMinimumSize = 8

	// ICMPv6DstUnreachableMinimumSize is the minimum size of a valid ICMP
	// destination unreachable packet.
	ICMPv6DstUnreachableMinimumSize = ICMPv6MinimumSize

	// ICMPv6PacketTooBigMinimumSize is the minimum size of a valid ICMP
	// packet-too-big packet.
	ICMPv6PacketTooBigMinimumSize = ICMPv6MinimumSize

	// icmpv6ChecksumOffset is the offset of the checksum field
	// in an ICMPv6 message.
	icmpv6ChecksumOffset = 2

	// icmpv6MTUOffset is the offset of the MTU field in an ICMPv6
	// PacketTooBig message.
	icmpv6MTUOffset = 4

	// icmpv6IdentOffset is the offset of the ident field
	// in a ICMPv6 Echo Request/Reply message.
	icmpv6IdentOffset = 4

	// icmpv6SequenceOffset is the offset of the sequence field
	// in a ICMPv6 Echo Request/Reply message.
	icmpv6SequenceOffset = 6
)

// ICMPv6Type is the ICMP type field described in RFC 4443 and friends.
type ICMPv6Type byte

// Typical values of ICMPv6Type defined in RFC 4443.
const (
	ICMPv6DstUnreachable ICMPv6Type = 1
	ICMPv6PacketTooBig   ICMPv6Type = 2
	ICMPv6TimeExceeded   ICMPv6Type = 3
	ICMPv6ParamProblem   ICMPv6Type = 4
	ICMPv6EchoRequest    ICMPv6Type = 128
	ICMPv6EchoReply      ICMPv6Type = 129

	// Neighbor Discovery Protocol (NDP) messages, see RFC 4861.

	ICMPv6RouterSolicit   ICMPv6Type = 133
	ICMPv6RouterAdvert    ICMPv6Type = 134
	ICMPv6NeighborSolicit ICMPv6Type = 135
	ICMPv6NeighborAdvert  ICMPv6Type = 136
	ICMPv6RedirectMsg     ICMPv6Type = 137
)

// Values for ICMP code as defined in RFC 4443.
const (
	ICMPv6PortUnreachable = 4
)

// Type is the ICMP type field.
func (b ICMPv6) Type() ICMPv6Type { return ICMPv6Type(b[0]) }

// SetType sets the ICMP type field.
func (b ICMPv6) SetType(t ICMPv6Type) { b[0] = byte(t) }

// Code is the ICMP code field. Its meaning depends on the value of Type.
func (b ICMPv6) Code() byte { return b[1] }

// SetCode sets the ICMP code field.
func (b ICMPv6) SetCode(c byte) { b[1] = c }

// Checksum is the ICMP checksum field.
func (b ICMPv6) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6ChecksumOffset:])
}

// SetChecksum calculates and sets the ICMP checksum field.
func (b ICMPv6) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[icmpv6ChecksumOffset:], checksum)
}

// SourcePort implements Transport.SourcePort.
func (ICMPv6) SourcePort() uint16 {
	return 0
}

// DestinationPort implements Transport.DestinationPort.
func (ICMPv6) DestinationPort() uint16 {
	return 0
}

// SetSourcePort implements Transport.SetSourcePort.
func (ICMPv6) SetSourcePort(uint16) {
}

// SetDestinationPort implements Transport.SetDestinationPort.
func (ICMPv6) SetDestinationPort(uint16) {
}

// MTU retrieves the MTU field from an ICMPv6 message.
func (b ICMPv6) MTU() uint32 {
	return binary.BigEndian.Uint32(b[icmpv6MTUOffset:])
}

// SetMTU sets the MTU field from an ICMPv6 message.
func (b ICMPv6) SetMTU(mtu uint32) {
	binary.BigEndian.PutUint32(b[icmpv6MTUOffset:], mtu)
}

// Ident retrieves the Ident field from an ICMPv6 message.
func (b ICMPv6) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6IdentOffset:])
}

// SetIdent sets the Ident field from an ICMPv6 message.
func (b ICMPv6) SetIdent(ident uint16) {
	binary.BigEndian.PutUint16(b[icmpv6IdentOffset:], ident)
}

// Sequence retrieves the Sequence field from an ICMPv6 message.
func (b ICMPv6) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6SequenceOffset:])
}

// SetSequence sets the Sequence field from an ICMPv6 message.
func (b ICMPv6) SetSequence(sequence uint16) {
	binary.BigEndian.PutUint16(b[icmpv6SequenceOffset:], sequence)
}

// NDPPayload returns the NDP payload buffer. That is, it returns the ICMPv6
// packet's message body as defined by RFC 4443 section 2.1; the portion of the
// ICMPv6 buffer after the first ICMPv6HeaderSize bytes.
func (b ICMPv6) NDPPayload() []byte {
	return b[ICMPv6HeaderSize:]
}

// Payload implements Transport.Payload.
func (b ICMPv6) Payload() []byte {
	return b[ICMPv6PayloadOffset:]
}

// ICMPv6Checksum calculates the ICMP checksum over the provided ICMP header,
// IPv6 src/dst addresses and the payload.
func ICMPv6Checksum(h ICMPv6, src, dst tcpip.Address, vv buffer.VectorisedView) uint16 {
	// Calculate the IPv6 pseudo-header upper-layer checksum.
	xsum := Checksum([]byte(src), 0)
	xsum = Checksum([]byte(dst), xsum)
	var upperLayerLength [4]byte
	binary.BigEndian.PutUint32(upperLayerLength[:], uint32(len(h)+vv.Size()))
	xsum = Checksum(upperLayerLength[:], xsum)
	xsum = Checksum([]byte{0, 0, 0, uint8(ICMPv6ProtocolNumber)}, xsum)
	for _, v := range vv.Views() {
		xsum = Checksum(v, xsum)
	}

	// h[2:4] is the checksum itself, set it aside to avoid checksumming the checksum.
	h2, h3 := h[2], h[3]
	h[2], h[3] = 0, 0
	xsum = ^Checksum(h, xsum)
	h[2], h[3] = h2, h3

	return xsum
}
