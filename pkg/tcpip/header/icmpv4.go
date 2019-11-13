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

// ICMPv4 represents an ICMPv4 header stored in a byte array.
type ICMPv4 []byte

const (
	// ICMPv4PayloadOffset defines the start of ICMP payload.
	ICMPv4PayloadOffset = 8

	// ICMPv4MinimumSize is the minimum size of a valid ICMP packet.
	ICMPv4MinimumSize = 8

	// ICMPv4ProtocolNumber is the ICMP transport protocol number.
	ICMPv4ProtocolNumber tcpip.TransportProtocolNumber = 1

	// icmpv4ChecksumOffset is the offset of the checksum field
	// in an ICMPv4 message.
	icmpv4ChecksumOffset = 2

	// icmpv4MTUOffset is the offset of the MTU field
	// in a ICMPv4FragmentationNeeded message.
	icmpv4MTUOffset = 6

	// icmpv4IdentOffset is the offset of the ident field
	// in a ICMPv4EchoRequest/Reply message.
	icmpv4IdentOffset = 4

	// icmpv4SequenceOffset is the offset of the sequence field
	// in a ICMPv4EchoRequest/Reply message.
	icmpv4SequenceOffset = 6
)

// ICMPv4Type is the ICMP type field described in RFC 792.
type ICMPv4Type byte

// Typical values of ICMPv4Type defined in RFC 792.
const (
	ICMPv4EchoReply      ICMPv4Type = 0
	ICMPv4DstUnreachable ICMPv4Type = 3
	ICMPv4SrcQuench      ICMPv4Type = 4
	ICMPv4Redirect       ICMPv4Type = 5
	ICMPv4Echo           ICMPv4Type = 8
	ICMPv4TimeExceeded   ICMPv4Type = 11
	ICMPv4ParamProblem   ICMPv4Type = 12
	ICMPv4Timestamp      ICMPv4Type = 13
	ICMPv4TimestampReply ICMPv4Type = 14
	ICMPv4InfoRequest    ICMPv4Type = 15
	ICMPv4InfoReply      ICMPv4Type = 16
)

// Values for ICMP code as defined in RFC 792.
const (
	ICMPv4PortUnreachable     = 3
	ICMPv4FragmentationNeeded = 4
)

// Type is the ICMP type field.
func (b ICMPv4) Type() ICMPv4Type { return ICMPv4Type(b[0]) }

// SetType sets the ICMP type field.
func (b ICMPv4) SetType(t ICMPv4Type) { b[0] = byte(t) }

// Code is the ICMP code field. Its meaning depends on the value of Type.
func (b ICMPv4) Code() byte { return b[1] }

// SetCode sets the ICMP code field.
func (b ICMPv4) SetCode(c byte) { b[1] = c }

// Checksum is the ICMP checksum field.
func (b ICMPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4ChecksumOffset:])
}

// SetChecksum sets the ICMP checksum field.
func (b ICMPv4) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[icmpv4ChecksumOffset:], checksum)
}

// SetPointer sets the ICMP pointer field.
func (b ICMPv4) SetPointer(pointer []byte) {
	copy(b[4:], pointer)
}

// SourcePort implements Transport.SourcePort.
func (ICMPv4) SourcePort() uint16 {
	return 0
}

// DestinationPort implements Transport.DestinationPort.
func (ICMPv4) DestinationPort() uint16 {
	return 0
}

// SetSourcePort implements Transport.SetSourcePort.
func (ICMPv4) SetSourcePort(uint16) {
}

// SetDestinationPort implements Transport.SetDestinationPort.
func (ICMPv4) SetDestinationPort(uint16) {
}

// Payload implements Transport.Payload.
func (b ICMPv4) Payload() []byte {
	return b[ICMPv4PayloadOffset:]
}

// MTU retrieves the MTU field from an ICMPv4 message.
func (b ICMPv4) MTU() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4MTUOffset:])
}

// SetMTU sets the MTU field from an ICMPv4 message.
func (b ICMPv4) SetMTU(mtu uint16) {
	binary.BigEndian.PutUint16(b[icmpv4MTUOffset:], mtu)
}

// Ident retrieves the Ident field from an ICMPv4 message.
func (b ICMPv4) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4IdentOffset:])
}

// SetIdent sets the Ident field from an ICMPv4 message.
func (b ICMPv4) SetIdent(ident uint16) {
	binary.BigEndian.PutUint16(b[icmpv4IdentOffset:], ident)
}

// Sequence retrieves the Sequence field from an ICMPv4 message.
func (b ICMPv4) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4SequenceOffset:])
}

// SetSequence sets the Sequence field from an ICMPv4 message.
func (b ICMPv4) SetSequence(sequence uint16) {
	binary.BigEndian.PutUint16(b[icmpv4SequenceOffset:], sequence)
}

// ICMPv4Checksum calculates the ICMP checksum over the provided ICMP header,
// and payload.
func ICMPv4Checksum(h ICMPv4, vv buffer.VectorisedView) uint16 {
	// Calculate the IPv6 pseudo-header upper-layer checksum.
	xsum := uint16(0)
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
